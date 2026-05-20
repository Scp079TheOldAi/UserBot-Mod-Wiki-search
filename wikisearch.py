

from .. import loader, utils
from telethon.tl.types import Message
import logging
import aiohttp
import asyncio
import urllib.parse
import re
import os
import tempfile
import json

logger = logging.getLogger(__name__)


@loader.tds
class WikiSearchMod(loader.Module):
    """Поиск информации на Wikipedia"""
    strings = {
        "name": "WikiSearch",
        "no_query": (
            "🚫 <b>Укажите поисковый запрос</b>\n\n"
            "<i>Примеры использования:</i>\n"
            "• <code>.wiki Python</code>\n"
            "• <code>.wiki Кыргызстан</code>\n"
            "• <code>.wiki en Linux</code>\n\n"
            "🇷🇺 По умолчанию поиск в русской Wikipedia\n"
            "🌍 Для другого языка: <code>.wiki en запрос</code>"
        ),
        "searching": "🔍 <b>Поиск в {} Wikipedia:</b>\n<code>{}</code>",
        "not_found": (
            "😔 <b>Ничего не найдено</b>\n\n"
            "Запрос: <code>{}</code>\n"
            "Wikipedia: {}\n\n"
            "<i>Попробуйте изменить формулировку или язык</i>"
        ),
        "error": "⚠️ <b>Ошибка при поиске</b>\n\n<i>Не удалось получить данные. Попробуйте позже</i>",
        "no_image": "\n\n🖼 <i>Статья не имеет изображения</i>",
        "result": (
            "📖 <b>{title}</b>\n\n"
            "{extract}\n\n"
            "🌐 <a href='{url}'>Читать полностью на Wikipedia</a>"
        ),
        "lang_ru": "русской",
        "lang_en": "английской",
    }

    strings_ru = {
        "no_query": (
            "🚫 <b>Укажите поисковый запрос</b>\n\n"
            "<i>Примеры использования:</i>\n"
            "• <code>.wiki Python</code>\n"
            "• <code>.wiki Кыргызстан</code>\n"
            "• <code>.wiki en Linux</code>\n\n"
            "🇷🇺 По умолчанию поиск в русской Wikipedia\n"
            "🌍 Для другого языка: <code>.wiki en запрос</code>"
        ),
        "searching": "🔍 <b>Поиск в {} Wikipedia:</b>\n<code>{}</code>",
        "not_found": (
            "😔 <b>Ничего не найдено</b>\n\n"
            "Запрос: <code>{}</code>\n"
            "Wikipedia: {}\n\n"
            "<i>Попробуйте изменить формулировку или язык</i>"
        ),
        "error": "⚠️ <b>Ошибка при поиске</b>\n\n<i>Не удалось получить данные. Попробуйте позже</i>",
        "no_image": "\n\n🖼 <i>Статья не имеет изображения</i>",
        "result": (
            "📖 <b>{title}</b>\n\n"
            "{extract}\n\n"
            "🌐 <a href='{url}'>Читать полностью на Wikipedia</a>"
        ),
        "lang_ru": "русской",
        "lang_en": "английской",
    }

    async def client_ready(self, client, db):
        self.client = client
        self.db = db
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ru-RU,ru;q=0.9",
        }

    async def _make_request(self, url, params=None, timeout=5):
        """Безопасный запрос"""
        try:
            connector = aiohttp.TCPConnector(force_close=True, limit=1)
            async with aiohttp.ClientSession(connector=connector, headers=self.headers) as session:
                async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if len(text) > 500000:
                            return None
                        return text
        except:
            pass
        return None

    async def _search_wiki(self, lang, query):
        """Поиск через API Wikipedia"""
        api_url = f"https://{lang}.wikipedia.org/w/api.php"
        
        # OpenSearch
        params = {
            "action": "opensearch",
            "search": query,
            "limit": 3,
            "format": "json"
        }
        
        text = await self._make_request(api_url, params, timeout=3)
        if text:
            try:
                data = json.loads(text)
                if len(data) >= 4 and data[1] and data[2] and data[3]:
                    title = data[1][0]
                    description = data[2][0]
                    url = data[3][0]
                    
                    if title and description:
                        return {
                            "title": title,
                            "extract": description,
                            "url": url,
                            "image": None
                        }
            except:
                pass
        
        # Query API
        params = {
            "action": "query",
            "prop": "extracts|pageimages",
            "exintro": 1,
            "explaintext": 1,
            "piprop": "thumbnail",
            "pithumbsize": 500,
            "titles": query,
            "format": "json",
            "redirects": 1
        }
        
        text = await self._make_request(api_url, params, timeout=3)
        if text:
            try:
                data = json.loads(text)
                pages = data.get("query", {}).get("pages", {})
                if pages:
                    page = list(pages.values())[0]
                    if "missing" not in page and page.get("extract"):
                        return {
                            "title": page.get("title", query),
                            "extract": page.get("extract", ""),
                            "url": f"https://{lang}.wikipedia.org/wiki/{urllib.parse.quote(page.get('title', query).replace(' ', '_'))}",
                            "image": page.get("thumbnail", {}).get("source")
                        }
            except:
                pass
        
        return None

    async def _download_image(self, url):
        """Скачивание изображения"""
        if not url:
            return None
        
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.read()
                        if 2048 < len(data) < 5242880:
                            ext = '.jpg'
                            ct = resp.headers.get('content-type', '').lower()
                            if 'png' in ct:
                                ext = '.png'
                            elif 'gif' in ct:
                                ext = '.gif'
                            
                            with tempfile.NamedTemporaryFile(delete=False, suffix=ext, prefix='wiki_') as tmp:
                                tmp.write(data)
                                return tmp.name
        except:
            pass
        return None

    def _prepare_text(self, text, max_len=600):
        """Подготовка текста"""
        if not text:
            return ""
        
        text = re.sub(r'<[^>]+>', '', text)
        text = text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        
        if len(text) > max_len:
            text = text[:max_len]
            for sep in ['. ', '! ', '? ', '\n']:
                pos = text.rfind(sep)
                if pos > max_len * 0.6:
                    text = text[:pos + 1]
                    break
            else:
                pos = text.rfind(' ')
                if pos > 0:
                    text = text[:pos]
            text += "..."
        
        text = text.replace('<', '&lt;').replace('>', '&gt;')
        
        parts = text.split('. ', 1)
        if len(parts) > 1:
            return f"<b>{parts[0]}.</b> {parts[1]}"
        return f"<b>{text}</b>"

    @loader.command(ru_doc="Поиск информации на Wikipedia")
    async def wikicmd(self, message: Message):
        """Поиск информации на Wikipedia"""
        
        try:
            args = utils.get_args_raw(message)
            reply = await message.get_reply_message()
            
            query = None
            lang = "ru"
            
            if args:
                parts = args.split(maxsplit=1)
                if len(parts) == 2 and len(parts[0]) == 2 and parts[0].isalpha():
                    lang = parts[0].lower()
                    query = parts[1].strip()
                else:
                    query = args.strip()
            elif reply and reply.text:
                query = reply.text.strip()
                parts = query.split(maxsplit=1)
                if len(parts) == 2 and len(parts[0]) == 2 and parts[0].isalpha():
                    lang = parts[0].lower()
                    query = parts[1].strip()
            
            if not query:
                await utils.answer(message, self.strings("no_query"))
                return
            
            lang_names = {"ru": "русской", "en": "английской"}
            lang_display = lang_names.get(lang, "Wikipedia")
            
            # Удаляем команду пользователя
            try:
                await message.delete()
            except:
                pass
            
            # Отправляем новое сообщение о поиске
            status_msg = await self.client.send_message(
                message.chat_id,
                self.strings("searching").format(lang_display, query)
            )
            
            result = await self._search_wiki(lang, query)
            
            if not result:
                try:
                    await status_msg.edit(self.strings("not_found").format(query, lang_display))
                except:
                    await self.client.send_message(
                        message.chat_id,
                        self.strings("not_found").format(query, lang_display)
                    )
                return
            
            title = result["title"]
            text = result["extract"]
            url = result["url"]
            image = result.get("image")
            
            link = f"\n\n🌐 <a href='{url}'>Читать полностью на Wikipedia</a>"
            no_img = self.strings("no_image") if not image else ""
            
            formatted = self._prepare_text(text)
            
            caption = f"📖 <b>{title}</b>\n\n{formatted}{link}{no_img}"
            
            image_path = None
            try:
                if image:
                    image_path = await self._download_image(image)
                
                if image_path and os.path.exists(image_path):
                    await self.client.send_file(
                        message.chat_id,
                        image_path,
                        caption=caption[:1024],
                        parse_mode='html'
                    )
                else:
                    await self.client.send_message(
                        message.chat_id,
                        caption[:4096],
                        parse_mode='html'
                    )
                
                # Удаляем статусное сообщение
                try:
                    await status_msg.delete()
                except:
                    pass
                    
            except Exception as e:
                logger.error(f"Send error: {e}")
                try:
                    await status_msg.edit(caption[:4096])
                except:
                    await self.client.send_message(
                        message.chat_id,
                        caption[:4096],
                        parse_mode='html'
                    )
            finally:
                if image_path and os.path.exists(image_path):
                    try:
                        os.unlink(image_path)
                    except:
                        pass
                        
        except Exception as e:
            logger.error(f"Critical error: {e}")
            try:
                await self.client.send_message(
                    message.chat_id,
                    self.strings("error")
                )
            except:
                pass