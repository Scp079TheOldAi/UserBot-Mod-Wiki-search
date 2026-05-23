# meta pic: https://t.me/Scp079ModulesAssets/2
# meta developer: @Scp079Modules
# scope: hikka_only
# meta banner: https://t.me/Scp079ModulesAssets/2

from .. import loader, utils
from telethon.tl.types import Message

import asyncio
import html
import logging
import os
import re
import tempfile
import time
import urllib.parse
from collections import OrderedDict

import aiohttp

logger = logging.getLogger(__name__)


@loader.tds
class WikiSearchMod(loader.Module):
    """Быстрый поиск статей на Wikipedia с изображениями, LRU+TTL-кэшем и защитой от дублей"""

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
        "error": (
            "⚠️ <b>Ошибка при поиске</b>\n\n"
            "<i>Не удалось получить данные. Попробуйте позже</i>"
        ),
        "no_image": "\n\n🖼 <i>Статья не имеет изображения</i>",
        "lang_ru": "русской",
        "lang_en": "английской",
        "cache_cleared": "🧹 <b>Кэш WikiSearch очищен</b>",
        "cache_stats": (
            "🧠 <b>Статистика кэша WikiSearch</b>\n\n"
            "Результаты: <code>{result_size}/{result_max}</code>\n"
            "Изображения: <code>{image_size}/{image_max}</code>\n"
            "Ожидающие запросы: <code>{inflight}</code>\n"
            "TTL результатов: <code>{result_ttl} сек</code>\n"
            "TTL изображений: <code>{image_ttl} сек</code>"
        ),
    }

    strings_ru = strings

    _SUPPORTED_LANG_RE = re.compile(r"^[a-z]{2,12}$")
    _MAX_TEXT_RESPONSE = 500_000
    _MAX_IMAGE_SIZE = 5 * 1024 * 1024
    _MIN_IMAGE_SIZE = 2 * 1024

    _RESULT_CACHE_TTL = 600
    _IMAGE_CACHE_TTL = 300
    _RESULT_CACHE_MAX = 256
    _IMAGE_CACHE_MAX = 64

    async def client_ready(self, client, db):
        self.client = client
        self.db = db
        self.headers = {
            "User-Agent": "WikiSearchMod/5.0 (+https://wikipedia.org)",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
        }
        self.timeout = aiohttp.ClientTimeout(total=6)
        self.connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=self.timeout,
            connector=self.connector,
        )
        self._result_cache = OrderedDict()
        self._image_cache = OrderedDict()
        self._inflight_results = {}
        self._inflight_images = {}

    async def on_unload(self):
        await self._cleanup_image_cache(remove_files=True)
        session = getattr(self, "session", None)
        if session and not session.closed:
            await session.close()

    def _now(self):
        return time.monotonic()

    def _result_cache_key(self, lang, query):
        return f"{lang}:{query.strip().casefold()}"

    def _image_cache_key(self, url):
        return url.strip()

    def _prune_ordered_cache(self, cache_obj, max_size):
        now = self._now()
        expired_keys = [key for key, value in cache_obj.items() if value[0] <= now]
        removed = []

        for key in expired_keys:
            removed.append(cache_obj.pop(key, None))

        while len(cache_obj) > max_size:
            _, value = cache_obj.popitem(last=False)
            removed.append(value)

        return [item for item in removed if item is not None]

    async def _cleanup_image_cache(self, remove_files=False):
        removed = self._prune_ordered_cache(self._image_cache, self._IMAGE_CACHE_MAX)
        if not remove_files:
            return

        for item in removed:
            if not item:
                continue
            _, payload = item
            path = payload.get("path") if isinstance(payload, dict) else None
            if path and os.path.isfile(path):
                try:
                    os.unlink(path)
                except OSError:
                    logger.debug("Failed to remove cached image file: %s", path)

        for _, payload in list(self._image_cache.values()):
            path = payload.get("path") if isinstance(payload, dict) else None
            if path and os.path.isfile(path):
                try:
                    os.unlink(path)
                except OSError:
                    logger.debug("Failed to remove cached image file: %s", path)

        self._image_cache.clear()

    def _get_result_cache(self, lang, query):
        key = self._result_cache_key(lang, query)
        item = self._result_cache.get(key)
        if not item:
            return None

        expires_at, payload = item
        if expires_at <= self._now():
            self._result_cache.pop(key, None)
            return None

        self._result_cache.move_to_end(key)
        return payload.copy() if isinstance(payload, dict) else payload

    def _set_result_cache(self, lang, query, payload):
        key = self._result_cache_key(lang, query)
        self._result_cache[key] = (
            self._now() + self._RESULT_CACHE_TTL,
            payload.copy() if isinstance(payload, dict) else payload,
        )
        self._result_cache.move_to_end(key)
        self._prune_ordered_cache(self._result_cache, self._RESULT_CACHE_MAX)

    def _get_image_cache(self, url):
        key = self._image_cache_key(url)
        item = self._image_cache.get(key)
        if not item:
            return None

        expires_at, payload = item
        path = payload.get("path") if isinstance(payload, dict) else None

        if expires_at <= self._now() or not path or not os.path.isfile(path):
            self._image_cache.pop(key, None)
            if path and os.path.isfile(path):
                try:
                    os.unlink(path)
                except OSError:
                    logger.debug("Failed to remove expired image file: %s", path)
            return None

        self._image_cache.move_to_end(key)
        return payload.copy()

    async def _set_image_cache(self, url, payload):
        key = self._image_cache_key(url)
        old_item = self._image_cache.pop(key, None)
        if old_item:
            _, old_payload = old_item
            old_path = old_payload.get("path") if isinstance(old_payload, dict) else None
            if old_path and old_path != payload.get("path") and os.path.isfile(old_path):
                try:
                    os.unlink(old_path)
                except OSError:
                    logger.debug("Failed to remove replaced image file: %s", old_path)

        self._image_cache[key] = (self._now() + self._IMAGE_CACHE_TTL, payload.copy())
        self._image_cache.move_to_end(key)

        removed = self._prune_ordered_cache(self._image_cache, self._IMAGE_CACHE_MAX)
        for item in removed:
            _, removed_payload = item
            removed_path = removed_payload.get("path") if isinstance(removed_payload, dict) else None
            if removed_path and os.path.isfile(removed_path):
                try:
                    os.unlink(removed_path)
                except OSError:
                    logger.debug("Failed to remove evicted image file: %s", removed_path)

    async def _request_json(self, url, params=None):
        try:
            async with self.session.get(url, params=params) as resp:
                if resp.status != 200:
                    logger.debug("Wikipedia API status %s for %s", resp.status, url)
                    return None

                text = await resp.text()
                if len(text) > self._MAX_TEXT_RESPONSE:
                    logger.warning("Wikipedia response too large: %s bytes", len(text))
                    return None

                return await resp.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug("Request error for %s: %s", url, e)
            return None
        except Exception:
            logger.exception("Unexpected error while requesting %s", url)
            return None

    async def _search_titles(self, lang, query):
        api_url = f"https://{lang}.wikipedia.org/w/api.php"
        params = {
            "action": "query",
            "list": "search",
            "srsearch": query,
            "srlimit": 1,
            "utf8": 1,
            "format": "json",
        }
        data = await self._request_json(api_url, params)
        if not data:
            return None

        results = data.get("query", {}).get("search", [])
        if not results:
            return None

        return results[0].get("title")

    async def _get_page_summary(self, lang, title):
        api_url = f"https://{lang}.wikipedia.org/w/api.php"
        params = {
            "action": "query",
            "prop": "extracts|pageimages|info",
            "inprop": "url",
            "exintro": 1,
            "explaintext": 1,
            "redirects": 1,
            "piprop": "thumbnail",
            "pithumbsize": 640,
            "titles": title,
            "format": "json",
        }
        data = await self._request_json(api_url, params)
        if not data:
            return None

        pages = data.get("query", {}).get("pages", {})
        if not pages:
            return None

        page = next(iter(pages.values()), None)
        if not page or "missing" in page:
            return None

        page_title = page.get("title") or title
        fullurl = page.get("fullurl") or (
            f"https://{lang}.wikipedia.org/wiki/{urllib.parse.quote(page_title.replace(' ', '_'))}"
        )
        extract = (page.get("extract") or "").strip()

        if not extract:
            return None

        return {
            "title": page_title,
            "extract": extract,
            "url": fullurl,
            "image": page.get("thumbnail", {}).get("source"),
        }

    async def _fetch_wiki_result(self, lang, query):
        title = await self._search_titles(lang, query)
        if not title and query != query.strip():
            title = await self._search_titles(lang, query.strip())

        if not title:
            title = query.strip()

        return await self._get_page_summary(lang, title)

    async def _search_wiki(self, lang, query):
        cached = self._get_result_cache(lang, query)
        if cached is not None:
            return cached

        key = self._result_cache_key(lang, query)
        task = self._inflight_results.get(key)

        if task is None:
            task = asyncio.create_task(self._fetch_wiki_result(lang, query))
            self._inflight_results[key] = task

        try:
            result = await task
        finally:
            self._inflight_results.pop(key, None)

        if result:
            self._set_result_cache(lang, query, result)

        return result

    async def _fetch_image_to_file(self, url):
        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return None

                data = await resp.read()
                if not (self._MIN_IMAGE_SIZE < len(data) < self._MAX_IMAGE_SIZE):
                    return None

                content_type = resp.headers.get("content-type", "").lower()
                ext = ".jpg"
                if "png" in content_type:
                    ext = ".png"
                elif "gif" in content_type:
                    ext = ".gif"
                elif "webp" in content_type:
                    ext = ".webp"

                with tempfile.NamedTemporaryFile(delete=False, suffix=ext, prefix="wiki_") as tmp:
                    tmp.write(data)
                    return {"path": tmp.name}
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug("Image download error: %s", e)
        except Exception:
            logger.exception("Unexpected image download error")

        return None

    async def _download_image(self, url):
        if not url:
            return None

        cached = self._get_image_cache(url)
        if cached:
            return cached.get("path")

        key = self._image_cache_key(url)
        task = self._inflight_images.get(key)

        if task is None:
            task = asyncio.create_task(self._fetch_image_to_file(url))
            self._inflight_images[key] = task

        try:
            payload = await task
        finally:
            self._inflight_images.pop(key, None)

        if payload and payload.get("path") and os.path.isfile(payload["path"]):
            await self._set_image_cache(url, payload)
            return payload["path"]

        return None

    def _prepare_text(self, text, max_len=900):
        if not text:
            return ""

        text = html.unescape(text)
        text = re.sub(r"\s+", " ", text).strip()

        if len(text) > max_len:
            trimmed = text[:max_len]
            split_pos = max(
                trimmed.rfind(". "),
                trimmed.rfind("! "),
                trimmed.rfind("? "),
                trimmed.rfind(" "),
            )
            if split_pos > int(max_len * 0.6):
                trimmed = trimmed[:split_pos].rstrip()
            text = trimmed + "..."

        safe = html.escape(text, quote=False)
        parts = re.split(r"(?<=[.!?])\s+", safe, maxsplit=1)

        if len(parts) == 2:
            return f"<b>{parts[0]}</b> {parts[1]}"

        return safe

    def _build_caption(self, lang, result):
        article_url = result.get("url") or (
            f"https://{lang}.wikipedia.org/wiki/"
            f"{urllib.parse.quote(result['title'].replace(' ', '_'))}"
        )
        title = html.escape(result["title"], quote=False)
        image_note = "" if result.get("image") else self.strings("no_image")

        link_html = (
            f"🌐 <a href='{html.escape(article_url, quote=True)}'>"
            "Читать полностью на Wikipedia</a>"
        )
        base_prefix = f"📖 <b>{title}</b>\n\n"
        base_suffix = f"\n\n{link_html}{image_note}"

        max_extract_len = max(120, 1024 - len(base_prefix) - len(base_suffix) - 32)
        formatted_text = self._prepare_text(result["extract"], max_len=max_extract_len)
        caption = f"{base_prefix}{formatted_text}{base_suffix}"

        if len(caption) > 1024:
            formatted_text = self._prepare_text(result["extract"], max_len=220)
            caption = f"{base_prefix}{formatted_text}{base_suffix}"

        if len(caption) > 1024:
            caption = f"{base_prefix}{link_html}{image_note}"

        return caption[:1024]

    def _parse_args(self, args, reply_text=None):
        source = args.strip() if args else (reply_text.strip() if reply_text else "")
        if not source:
            return "ru", None

        parts = source.split(maxsplit=1)
        lang = "ru"
        query = source

        if len(parts) == 2 and self._SUPPORTED_LANG_RE.fullmatch(parts[0].lower()):
            lang = parts[0].lower()
            query = parts[1].strip()

        return lang, query.strip() or None

    @loader.command(ru_doc="Поиск информации на Wikipedia")
    async def wikicmd(self, message: Message):
        """Поиск информации на Wikipedia"""
        status_msg = None

        try:
            args = utils.get_args_raw(message)
            reply = await message.get_reply_message()
            reply_text = reply.text if reply and getattr(reply, "text", None) else None

            lang, query = self._parse_args(args, reply_text)
            if not query:
                await utils.answer(message, self.strings("no_query"))
                return

            lang_names = {
                "ru": self.strings("lang_ru"),
                "en": self.strings("lang_en"),
            }
            lang_display = lang_names.get(lang, lang)
            safe_query = html.escape(query, quote=False)

            try:
                await message.delete()
            except Exception:
                pass

            status_msg = await self.client.send_message(
                message.chat_id,
                self.strings("searching").format(lang_display, safe_query),
                parse_mode="html",
            )

            result = await self._search_wiki(lang, query)
            if not result:
                await status_msg.edit(
                    self.strings("not_found").format(
                        safe_query,
                        html.escape(lang_display, quote=False),
                    ),
                    parse_mode="html",
                )
                return

            caption = self._build_caption(lang, result)

            image_path = None
            if result.get("image"):
                image_path = await self._download_image(result["image"])

            if image_path and os.path.isfile(image_path):
                await self.client.send_file(
                    message.chat_id,
                    image_path,
                    caption=caption,
                    parse_mode="html",
                    force_document=False,
                )
            else:
                await self.client.send_message(
                    message.chat_id,
                    caption,
                    parse_mode="html",
                    link_preview=False,
                )

            if status_msg:
                await status_msg.delete()

        except Exception:
            logger.exception("Critical error in wikicmd")
            error_text = self.strings("error")
            try:
                if status_msg:
                    await status_msg.edit(error_text, parse_mode="html")
                else:
                    await self.client.send_message(
                        message.chat_id,
                        error_text,
                        parse_mode="html",
                    )
            except Exception:
                logger.exception("Failed to send error message")

    @loader.command(ru_doc="Очистить кэш WikiSearch")
    async def wikiclearcmd(self, message: Message):
        """Очистить кэш WikiSearch"""
        self._result_cache.clear()
        await self._cleanup_image_cache(remove_files=True)
        self._inflight_results.clear()
        self._inflight_images.clear()
        await utils.answer(message, self.strings("cache_cleared"))

    @loader.command(ru_doc="Показать статистику кэша WikiSearch")
    async def wikicachecmd(self, message: Message):
        """Показать статистику кэша WikiSearch"""
        self._prune_ordered_cache(self._result_cache, self._RESULT_CACHE_MAX)
        await self._cleanup_image_cache(remove_files=False)
        await utils.answer(
            message,
            self.strings("cache_stats").format(
                result_size=len(self._result_cache),
                result_max=self._RESULT_CACHE_MAX,
                image_size=len(self._image_cache),
                image_max=self._IMAGE_CACHE_MAX,
                inflight=len(self._inflight_results) + len(self._inflight_images),
                result_ttl=self._RESULT_CACHE_TTL,
                image_ttl=self._IMAGE_CACHE_TTL,
            ),
        )
