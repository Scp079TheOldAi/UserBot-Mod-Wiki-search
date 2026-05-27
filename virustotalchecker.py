# modules/vtcheck.py
# requires: aiohttp
# scope: pip
# (c) @Scp079OldAi
# License: MIT - You can modify this file but must keep author credit

import asyncio
import base64
import hashlib
import math
import os
import re
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import aiohttp
from hikka import loader, utils

VT_API = "https://www.virustotal.com/api/v3"
CACHE_TTL = 60 * 20
BIG_FILE_THRESHOLD = 32 * 1024 * 1024
MAX_FILE_SIZE_HARD = 650 * 1024 * 1024
PAGE_SIZE = 10
HTTP_TOTAL_TIMEOUT = 180
ANALYSIS_POLLS = 20
ANALYSIS_DELAY = 8


@dataclass
class CachedResult:
    created_at: float
    data: dict


@loader.tds
class VirusTotalChecker(loader.Module):
    """VirusTotal checker with config-based API key setup"""

    strings = {"name": "VirusTotalChecker"}

    strings_ru = {
        "config_missing": "❌ API-ключ VirusTotal не настроен. Укажите его через конфиг модуля.",
        "no_input": "❌ Объект для проверки не указан.\n\nОтветьте на файл или сообщение со ссылкой, либо передайте ссылку в тексте команды.",
        "downloading": "📥 Выполняется загрузка файла...",
        "uploading": "📤 Выполняется отправка файла на анализ...\n📄 Имя: {filename}\n📦 Размер: {size}",
        "checking_url": "🔗 Выполняется проверка URL...\n{url}",
        "rechecking_url": "🔄 Выполняется повторный анализ URL...\n{url}",
        "reanalyzing_file": "🔄 Выполняется повторный анализ файла...\n{sha256}",
        "too_big": "❌ Размер файла превышает допустимый предел VirusTotal.\nМаксимум: до 650 МБ через upload URL\nРазмер файла: {size}",
        "download_error": "❌ Не удалось загрузить файл.\n{error}",
        "bad_request": "❌ Запрос отклонён API. Проверьте корректность файла или ссылки.",
        "server_error": "❌ Сервис VirusTotal временно недоступен. Повторите попытку позднее.",
        "network_error": "❌ Произошла сетевая ошибка при обращении к VirusTotal.",
        "timeout_error": "⚠️ Время ожидания результата анализа истекло.",
        "rate_limit": "⚠️ VirusTotal временно ограничил количество запросов. Повторите попытку позднее.",
        "file_not_found": "❌ Отчёт по файлу в базе VirusTotal не найден.",
        "url_not_found": "❌ Отчёт по указанному URL в базе VirusTotal не найден.",
        "parse_error": "❌ Не удалось обработать ответ API VirusTotal.",
        "api_error": "❌ Ошибка API: {error}",
        "status_text": "🛡️ VirusTotal\n• Записей в кэше: {cache_items}\n• TTL кэша: {ttl} мин\n• Ключ в конфиге: {cfg}",
        "results_file": (
            "🛡️ ОТЧЁТ ПО ФАЙЛУ\n\n"
            "📄 Имя: {filename}\n"
            "📦 Размер: {size}\n"
            "📁 Формат: {filetype}\n"
            "🔑 SHA-256: {sha256}\n\n"
        ),
        "results_url": (
            "🛡️ ОТЧЁТ ПО URL\n\n"
            "🔗 Адрес: {url}\n\n"
        ),
        "stats_line": (
            "📊 Результаты анализа:\n"
            "🔴 Вредоносные: {malicious}\n"
            "🟡 Подозрительные: {suspicious}\n"
            "🟢 Безопасные: {harmless}\n"
            "⚪ Не обнаружено: {undetected}\n"
            "🟠 Ошибки анализа: {failure}\n"
            "⏱ Таймауты: {timeout}"
        ),
        "detections_page": "\n\n⚠️ Сработавшие движки: {count}\n📄 Страница {page}/{pages}",
        "detection_item": "\n• {engine}: {threat}",
        "no_detections": "\n\n✅ По доступным данным вредоносных или подозрительных срабатываний не зафиксировано.",
        "deleted": "🗑 Сообщение удалено.",
        "inline_expired": "⌛ Время жизни интерактивного сообщения истекло.",
        "btn_prev": "◀ Назад",
        "btn_next": "▶ Вперёд",
        "btn_delete": "🗑 Удалить",
        "btn_report": "📄 Отчёт",
        "btn_recheck": "🔄 Повторить",
        "help_text": (
            "🛡️ VirusTotalChecker — справка\n\n"
            "Настройка API-ключа:\n"
            "1. Открой https://www.virustotal.com и войди в аккаунт.\n"
            "2. Перейди на страницу API-ключа:\n"
            "   https://www.virustotal.com/gui/my-apikey\n"
            "3. Скопируй персональный API-ключ.\n"
            "4. Открой конфиг модуля: .cfg VirusTotalChecker\n"
            "5. В параметре api_key укажи скопированный ключ.\n\n"
            "Важно:\n"
            "• Не отправляй API-ключ в открытые чаты.\n"
            "• Храни ключ только в конфиге модуля.\n\n"
            "Команды:\n"
            "• {prefix}vtcheck <url> — проверить ссылку\n"
            "• Ответ на файл + {prefix}vtcheck — проверить файл\n"
            "• {prefix}vtrecheck <url> — повторный анализ ссылки\n"
            "• Ответ на файл + {prefix}vtrecheck — повторный анализ файла\n"
            "• {prefix}vtstatus — состояние модуля\n"
            "• {prefix}vthelp — показать эту справку"
        ),
    }

    strings_en = {
        "config_missing": "❌ VirusTotal API key is not configured. Set it through module config.",
        "no_input": "❌ No object was provided for analysis.\n\nReply to a file or a message with a URL, or pass a URL in the command text.",
        "downloading": "📥 Downloading file...",
        "uploading": "📤 Uploading file for analysis...\n📄 Name: {filename}\n📦 Size: {size}",
        "checking_url": "🔗 Checking URL...\n{url}",
        "rechecking_url": "🔄 Reanalyzing URL...\n{url}",
        "reanalyzing_file": "🔄 Reanalyzing file...\n{sha256}",
        "too_big": "❌ File size exceeds the VirusTotal limit.\nMaximum: up to 650 MB via upload URL\nFile size: {size}",
        "download_error": "❌ Failed to download the file.\n{error}",
        "bad_request": "❌ The request was rejected by the API. Verify the file or URL.",
        "server_error": "❌ VirusTotal is temporarily unavailable. Try again later.",
        "network_error": "❌ A network error occurred while contacting VirusTotal.",
        "timeout_error": "⚠️ The analysis result was not received in time.",
        "rate_limit": "⚠️ VirusTotal temporarily limited requests. Try again later.",
        "file_not_found": "❌ No VirusTotal report was found for the file.",
        "url_not_found": "❌ No VirusTotal report was found for the URL.",
        "parse_error": "❌ Failed to process the VirusTotal API response.",
        "api_error": "❌ API error: {error}",
        "status_text": "🛡️ VirusTotal\n• Cached entries: {cache_items}\n• Cache TTL: {ttl} min\n• Key in config: {cfg}",
        "results_file": (
            "🛡️ FILE REPORT\n\n"
            "📄 Name: {filename}\n"
            "📦 Size: {size}\n"
            "📁 Format: {filetype}\n"
            "🔑 SHA-256: {sha256}\n\n"
        ),
        "results_url": (
            "🛡️ URL REPORT\n\n"
            "🔗 Address: {url}\n\n"
        ),
        "stats_line": (
            "📊 Analysis results:\n"
            "🔴 Malicious: {malicious}\n"
            "🟡 Suspicious: {suspicious}\n"
            "🟢 Harmless: {harmless}\n"
            "⚪ Undetected: {undetected}\n"
            "🟠 Analysis failures: {failure}\n"
            "⏱ Timeouts: {timeout}"
        ),
        "detections_page": "\n\n⚠️ Triggered engines: {count}\n📄 Page {page}/{pages}",
        "detection_item": "\n• {engine}: {threat}",
        "no_detections": "\n\n✅ No malicious or suspicious detections were reported by the available engines.",
        "deleted": "🗑 Message deleted.",
        "inline_expired": "⌛ The interactive message has expired.",
        "btn_prev": "◀ Prev",
        "btn_next": "▶ Next",
        "btn_delete": "🗑 Delete",
        "btn_report": "📄 Report",
        "btn_recheck": "🔄 Recheck",
        "help_text": (
            "🛡️ VirusTotalChecker — help\n\n"
            "API key setup:\n"
            "1. Open https://www.virustotal.com and sign in.\n"
            "2. Open your API key page:\n"
            "   https://www.virustotal.com/gui/my-apikey\n"
            "3. Copy your personal API key.\n"
            "4. Open module config: .cfg VirusTotalChecker\n"
            "5. Paste the copied key into the api_key field.\n\n"
            "Important:\n"
            "• Do not send your API key in public chats.\n"
            "• Store the key only in module config.\n\n"
            "Commands:\n"
            "• {prefix}vtcheck <url> — check URL\n"
            "• Reply to a file + {prefix}vtcheck — check file\n"
            "• {prefix}vtrecheck <url> — reanalyze URL\n"
            "• Reply to a file + {prefix}vtrecheck — reanalyze file\n"
            "• {prefix}vtstatus — module status\n"
            "• {prefix}vthelp — show this help"
        ),
    }

    def __init__(self):
        self.client = None
        self.db = None
        self.lang = "ru"
        self.prefix = "."
        self.cache: Dict[str, CachedResult] = {}
        self.inline_states: Dict[str, CachedResult] = {}
        self.last_429_until = 0.0
        self.last_backoff = 2.0

        self.config = loader.ModuleConfig(
            loader.ConfigValue(
                "api_key",
                "",
                lambda: (
                    "VirusTotal API key. Open https://www.virustotal.com/gui/my-apikey "
                    "while signed in, copy your personal API key and paste it here. "
                    "Do not send the key in public chats."
                ),
                validator=loader.validators.Hidden(loader.validators.String()),
            )
        )

    async def client_ready(self, client, db):
        self.client = client
        self.db = db
        self.lang = db.get("hikka.loader", "lang", "ru")
        self.prefix = db.get("hikka.loader", "prefix", ".")

    @property
    def api_key(self):
        return (self.config["api_key"] or "").strip()

    def _(self, key, **kwargs):
        strings = self.strings_ru if self.lang == "ru" else self.strings_en
        text = strings.get(key, key)
        return text.format(**kwargs) if kwargs else text

    def _headers(self):
        return {"x-apikey": self.api_key}

    def _cache_get(self, key: str):
        item = self.cache.get(key)
        if not item:
            return None
        if time.time() - item.created_at > CACHE_TTL:
            self.cache.pop(key, None)
            return None
        return item.data

    def _cache_set(self, key: str, data: dict):
        self.cache[key] = CachedResult(time.time(), data)

    def _inline_get(self, key: str):
        item = self.inline_states.get(key)
        if not item:
            return None
        if time.time() - item.created_at > CACHE_TTL:
            self.inline_states.pop(key, None)
            return None
        return item.data

    def _inline_set(self, key: str, data: dict):
        self.inline_states[key] = CachedResult(time.time(), data)

    def _clean_url(self, raw: Optional[str]) -> Optional[str]:
        raw = (raw or "").strip()
        if not raw:
            return None
        if raw.startswith(("http://", "https://")):
            return raw
        if "." in raw and " " not in raw:
            return f"https://{raw}"
        return None

    def _extract_url(self, text: Optional[str]) -> Optional[str]:
        if not text:
            return None
        pattern = (
            r"(?:https?://)?(?:www\.)?"
            r"[-a-zA-Z0-9@:%._\+~#=]{1,256}"
            r"\.[a-zA-Z0-9()]{1,24}\b"
            r"(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)"
        )
        found = re.findall(pattern, text)
        return self._clean_url(found[0]) if found else None

    def _format_size(self, size: int) -> str:
        if size < 1024:
            return f"{size} Б" if self.lang == "ru" else f"{size} B"
        if size < 1024 * 1024:
            return f"{size / 1024:.1f} КБ" if self.lang == "ru" else f"{size / 1024:.1f} KB"
        return f"{size / (1024 * 1024):.1f} МБ" if self.lang == "ru" else f"{size / (1024 * 1024):.1f} MB"

    def _get_file_type(self, filename: str) -> str:
        ext = os.path.splitext(filename or "")[1].lower()
        return ext[1:].upper() if ext else ("Не определён" if self.lang == "ru" else "Unknown")

    def _url_id(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _report_url(self, result: dict) -> str:
        if result["type"] == "file":
            return f"https://www.virustotal.com/gui/file/{result['sha256']}/detection"
        return f"https://www.virustotal.com/gui/url/{result['id']}/detection"

    def _state_key(self, result: dict) -> str:
        base = result["sha256"] if result["type"] == "file" else result["id"]
        return hashlib.md5(base.encode()).hexdigest()[:16]

    async def _respect_backoff(self):
        now = time.time()
        if now < self.last_429_until:
            await asyncio.sleep(self.last_429_until - now)

    async def _request(self, session, method: str, url: str, *, retry: int = 4, **kwargs):
        if not self.api_key:
            return {"error": "auth"}

        await self._respect_backoff()

        headers = dict(self._headers())
        headers.update(kwargs.pop("headers", {}))
        timeout = kwargs.pop("timeout", aiohttp.ClientTimeout(total=HTTP_TOTAL_TIMEOUT))

        try:
            async with session.request(method, url, headers=headers, timeout=timeout, **kwargs) as resp:
                if resp.status in (200, 201):
                    self.last_backoff = 2.0
                    ctype = resp.headers.get("Content-Type", "")
                    if "application/json" in ctype:
                        return await resp.json()
                    return {"ok": True, "status": resp.status}

                if resp.status == 204:
                    self.last_backoff = 2.0
                    return {"ok": True, "status": 204}

                if resp.status == 400:
                    try:
                        data = await resp.json()
                    except Exception:
                        data = {}
                    return {"error": "bad_request", "details": data}

                if resp.status == 401:
                    return {"error": "auth"}

                if resp.status == 404:
                    return None

                if resp.status == 429:
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        wait_for = max(1, int(retry_after))
                    else:
                        wait_for = int(min(self.last_backoff, 60))
                        self.last_backoff = min(self.last_backoff * 2, 60)
                    self.last_429_until = time.time() + wait_for
                    if retry > 0:
                        await asyncio.sleep(wait_for)
                        return await self._request(session, method, url, retry=retry - 1, **kwargs)
                    return {"error": "ratelimit"}

                if resp.status >= 500:
                    wait_for = int(min(self.last_backoff, 30))
                    self.last_backoff = min(self.last_backoff * 2, 30)
                    if retry > 0:
                        await asyncio.sleep(wait_for)
                        return await self._request(session, method, url, retry=retry - 1, **kwargs)
                    return {"error": "server"}

                return {"error": f"http_{resp.status}"}

        except asyncio.TimeoutError:
            if retry > 0:
                await asyncio.sleep(2)
                return await self._request(session, method, url, retry=retry - 1, **kwargs)
            return {"error": "timeout"}
        except aiohttp.ClientError:
            return {"error": "network"}

    async def _analysis_wait(self, session, analysis_id: str):
        for _ in range(ANALYSIS_POLLS):
            data = await self._request(session, "GET", f"{VT_API}/analyses/{analysis_id}")
            if not data or (isinstance(data, dict) and data.get("error")):
                return data
            try:
                status = data["data"]["attributes"]["status"]
            except (KeyError, TypeError):
                return {"error": "parse"}
            if status == "completed":
                return data
            await asyncio.sleep(ANALYSIS_DELAY)
        return {"error": "timeout"}

    def _collect_threats(self, results: dict) -> List[Tuple[str, str]]:
        threats = []
        for engine, val in (results or {}).items():
            category = val.get("category")
            result = (val.get("result") or "").strip()
            if category in ("malicious", "suspicious") and result and result.lower() not in {"clean", "undetected"}:
                threats.append((engine, result))
        threats.sort(key=lambda x: x[0].lower())
        return threats

    async def _get_large_upload_url(self, session) -> Optional[str]:
        data = await self._request(session, "GET", f"{VT_API}/files/upload_url")
        if not data or (isinstance(data, dict) and data.get("error")):
            return None
        return data.get("data")

    async def _upload_file(self, session, filepath: str, filename: str, size: int):
        if size > MAX_FILE_SIZE_HARD:
            return {"error": "too_big"}

        target_url = f"{VT_API}/files"
        if size > BIG_FILE_THRESHOLD:
            upload_url = await self._get_large_upload_url(session)
            if not upload_url:
                return {"error": "upload_url"}
            target_url = upload_url

        form = aiohttp.FormData()
        with open(filepath, "rb") as f:
            form.add_field("file", f, filename=filename)
            return await self._request(session, "POST", target_url, data=form)

    async def _get_file_report(self, session, sha256: str):
        data = await self._request(session, "GET", f"{VT_API}/files/{sha256}")
        if data is None:
            return None
        if isinstance(data, dict) and data.get("error"):
            return data
        try:
            attrs = data["data"]["attributes"]
            return {
                "type": "file",
                "sha256": sha256,
                "stats": attrs.get("last_analysis_stats", {}),
                "threats": self._collect_threats(attrs.get("last_analysis_results", {})),
            }
        except (KeyError, TypeError):
            return {"error": "parse"}

    async def _reanalyze_file(self, session, sha256: str):
        data = await self._request(session, "POST", f"{VT_API}/files/{sha256}/analyse")
        if not data or (isinstance(data, dict) and data.get("error")):
            return data
        try:
            analysis_id = data["data"]["id"]
        except (KeyError, TypeError):
            return {"error": "parse"}
        wait = await self._analysis_wait(session, analysis_id)
        if wait and isinstance(wait, dict) and wait.get("error"):
            return wait
        return await self._get_file_report(session, sha256)

    async def _scan_file(self, sha256: str, filepath: Optional[str] = None, filename: str = "file.bin", force: bool = False):
        cache_key = f"file:{sha256}:{int(force)}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        async with aiohttp.ClientSession() as session:
            if force:
                result = await self._reanalyze_file(session, sha256)
                if result and not (isinstance(result, dict) and result.get("error")):
                    self._cache_set(cache_key, result)
                return result

            existing = await self._get_file_report(session, sha256)
            if existing and not (isinstance(existing, dict) and existing.get("error")):
                self._cache_set(cache_key, existing)
                return existing

            if isinstance(existing, dict) and existing.get("error"):
                return existing

            if not filepath:
                return None

            size = os.path.getsize(filepath)
            upload = await self._upload_file(session, filepath, filename, size)
            if not upload or (isinstance(upload, dict) and upload.get("error")):
                return upload

            try:
                analysis_id = upload["data"]["id"]
            except (KeyError, TypeError):
                return {"error": "parse"}

            wait = await self._analysis_wait(session, analysis_id)
            if wait and isinstance(wait, dict) and wait.get("error"):
                return wait

            final = await self._get_file_report(session, sha256)
            if final and not (isinstance(final, dict) and final.get("error")):
                self._cache_set(cache_key, final)
            return final

    async def _get_url_report(self, session, url: str):
        url_id = self._url_id(url)
        data = await self._request(session, "GET", f"{VT_API}/urls/{url_id}")
        if data is None:
            return None
        if isinstance(data, dict) and data.get("error"):
            return data
        try:
            attrs = data["data"]["attributes"]
            return {
                "type": "url",
                "url": url,
                "id": url_id,
                "stats": attrs.get("last_analysis_stats", {}),
                "threats": self._collect_threats(attrs.get("last_analysis_results", {})),
            }
        except (KeyError, TypeError):
            return {"error": "parse"}

    async def _submit_url(self, session, url: str):
        data = await self._request(session, "POST", f"{VT_API}/urls", data={"url": url})
        if not data or (isinstance(data, dict) and data.get("error")):
            return data
        try:
            analysis_id = data["data"]["id"]
        except (KeyError, TypeError):
            return {"error": "parse"}
        wait = await self._analysis_wait(session, analysis_id)
        if wait and isinstance(wait, dict) and wait.get("error"):
            return wait
        return await self._get_url_report(session, url)

    async def _scan_url(self, url: str, force: bool = False):
        cache_key = f"url:{self._url_id(url)}:{int(force)}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        async with aiohttp.ClientSession() as session:
            if not force:
                existing = await self._get_url_report(session, url)
                if existing and not (isinstance(existing, dict) and existing.get("error")):
                    self._cache_set(cache_key, existing)
                    return existing
                if isinstance(existing, dict) and existing.get("error") and existing.get("error") != "bad_request":
                    return existing

            result = await self._submit_url(session, url)
            if result and not (isinstance(result, dict) and result.get("error")):
                self._cache_set(cache_key, result)
            return result

    async def _compute_sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _render_result_text(self, state: dict) -> str:
        res = state["result"]
        meta = state["meta"]
        page = state["page"]

        if res["type"] == "file":
            text = self._(
                "results_file",
                filename=meta["filename"],
                size=meta["size"],
                filetype=meta["filetype"],
                sha256=meta["sha256"],
            )
        else:
            text = self._("results_url", url=meta["url"])

        stats = res.get("stats", {})
        text += self._(
            "stats_line",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            failure=stats.get("failure", 0),
            timeout=stats.get("timeout", 0),
        )

        threats = res.get("threats", [])
        if not threats:
            text += self._("no_detections")
            return text

        pages = max(1, math.ceil(len(threats) / PAGE_SIZE))
        page = max(1, min(page, pages))
        start = (page - 1) * PAGE_SIZE
        end = start + PAGE_SIZE

        text += self._("detections_page", count=len(threats), page=page, pages=pages)
        for engine, threat in threats[start:end]:
            text += self._("detection_item", engine=engine, threat=threat)

        return text

    def _build_markup(self, state_key: str):
        state = self._inline_get(state_key)
        if not state:
            return [[{"text": self._("btn_delete"), "callback": self._cb_delete, "args": (state_key,)}]]

        res = state["result"]
        threats = res.get("threats", [])
        pages = max(1, math.ceil(max(1, len(threats)) / PAGE_SIZE))
        page = state["page"]
        report_url = self._report_url(res)

        nav_row = []
        if threats and pages > 1:
            nav_row = [
                {"text": self._("btn_prev"), "callback": self._cb_prev, "args": (state_key,)},
                {"text": f"{page}/{pages}", "callback": self._cb_noop, "args": (state_key,)},
                {"text": self._("btn_next"), "callback": self._cb_next, "args": (state_key,)},
            ]

        action_row = [
            {"text": self._("btn_report"), "url": report_url},
            {"text": self._("btn_recheck"), "callback": self._cb_recheck, "args": (state_key,)},
            {"text": self._("btn_delete"), "callback": self._cb_delete, "args": (state_key,)},
        ]

        markup = []
        if nav_row:
            markup.append(nav_row)
        markup.append(action_row)
        return markup

    async def _answer_inline(self, msg, state: dict):
        state_key = self._state_key(state["result"])
        self._inline_set(state_key, state)

        text = self._render_result_text(state)
        markup = self._build_markup(state_key)

        if hasattr(self, "inline") and hasattr(self.inline, "form"):
            await self.inline.form(
                text=text,
                message=msg,
                reply_markup=markup,
                disable_security=True,
            )
            return

        await utils.answer(msg, text)

    async def _edit_inline(self, call, state_key: str):
        state = self._inline_get(state_key)
        if not state:
            try:
                await call.answer(self._("inline_expired"), show_alert=True)
            except Exception:
                pass
            return

        text = self._render_result_text(state)
        markup = self._build_markup(state_key)

        try:
            await call.edit(text, reply_markup=markup)
        except Exception:
            try:
                await call.answer(self._("inline_expired"), show_alert=True)
            except Exception:
                pass

    async def _cb_noop(self, call, state_key: str):
        try:
            await call.answer()
        except Exception:
            pass

    async def _cb_prev(self, call, state_key: str):
        state = self._inline_get(state_key)
        if not state:
            await call.answer(self._("inline_expired"), show_alert=True)
            return
        state["page"] = max(1, state["page"] - 1)
        self._inline_set(state_key, state)
        await self._edit_inline(call, state_key)

    async def _cb_next(self, call, state_key: str):
        state = self._inline_get(state_key)
        if not state:
            await call.answer(self._("inline_expired"), show_alert=True)
            return
        threats = state["result"].get("threats", [])
        pages = max(1, math.ceil(max(1, len(threats)) / PAGE_SIZE))
        state["page"] = min(pages, state["page"] + 1)
        self._inline_set(state_key, state)
        await self._edit_inline(call, state_key)

    async def _cb_delete(self, call, state_key: str):
        self.inline_states.pop(state_key, None)
        try:
            await call.delete()
        except Exception:
            try:
                await call.edit(self._("deleted"), reply_markup=None)
            except Exception:
                pass

    async def _cb_recheck(self, call, state_key: str):
        state = self._inline_get(state_key)
        if not state:
            await call.answer(self._("inline_expired"), show_alert=True)
            return

        try:
            await call.answer()
        except Exception:
            pass

        res = state["result"]
        if res["type"] == "url":
            new_res = await self._scan_url(state["meta"]["url"], force=True)
        else:
            new_res = await self._scan_file(
                state["meta"]["sha256"],
                filepath=None,
                filename=state["meta"]["filename"],
                force=True,
            )

        if not new_res or (isinstance(new_res, dict) and new_res.get("error")):
            err = new_res.get("error", "unknown") if isinstance(new_res, dict) else "unknown"
            try:
                await call.answer(self._("api_error", error=err), show_alert=True)
            except Exception:
                pass
            return

        state["result"] = new_res
        state["page"] = 1
        self._inline_set(state_key, state)
        await self._edit_inline(call, state_key)

    async def _show_error(self, msg_or_status, err: str):
        mapping = {
            "auth": self._("config_missing"),
            "bad_request": self._("bad_request"),
            "server": self._("server_error"),
            "network": self._("network_error"),
            "timeout": self._("timeout_error"),
            "ratelimit": self._("rate_limit"),
            "parse": self._("parse_error"),
            "too_big": self._("too_big", size=">650 MB"),
            "upload_url": self._("api_error", error="upload_url"),
        }
        text = mapping.get(err, self._("api_error", error=err))
        try:
            await msg_or_status.edit(text)
        except Exception:
            await utils.answer(msg_or_status, text)

    @loader.command()
    async def vthelpcmd(self, msg):
        """Показать справку по настройке API-ключа и использованию модуля"""
        await utils.answer(msg, self._("help_text", prefix=self.prefix))

    @loader.command()
    async def vtstatuscmd(self, msg):
        """Показать состояние модуля и статус локального кэша"""
        cfg = "да" if self.api_key and self.lang == "ru" else "yes" if self.api_key else "нет" if self.lang == "ru" else "no"
        await utils.answer(
            msg,
            self._("status_text", cache_items=len(self.cache) + len(self.inline_states), ttl=CACHE_TTL // 60, cfg=cfg),
        )

    @loader.command()
    async def vtcheckcmd(self, msg):
        """Проверить файл или ссылку через VirusTotal"""
        await self._run_check(msg, force=False)

    @loader.command()
    async def vtrecheckcmd(self, msg):
        """Запустить повторный анализ файла или ссылки в VirusTotal"""
        await self._run_check(msg, force=True)

    async def _run_check(self, msg, force: bool = False):
        if not self.api_key:
            await utils.answer(msg, self._("config_missing"))
            return

        tmpfile = None

        try:
            cmd_args = utils.get_args_raw(msg)
            url = self._extract_url(cmd_args)

            if url:
                status = await utils.answer(
                    msg,
                    self._("rechecking_url" if force else "checking_url", url=url[:200]),
                )
                res = await self._scan_url(url, force=force)
                if isinstance(res, dict) and res.get("error"):
                    await self._show_error(status, res["error"])
                    return

                state = {
                    "page": 1,
                    "result": res,
                    "meta": {"url": url},
                }
                await status.delete()
                await self._answer_inline(msg, state)
                return

            if msg.reply_to:
                reply = await msg.get_reply_message()

                if getattr(reply, "document", None):
                    status = await utils.answer(msg, self._("downloading"))
                    try:
                        tmpfile = await self.client.download_media(reply, tempfile.gettempdir())
                    except Exception as e:
                        await status.edit(self._("download_error", error=str(e)[:120]))
                        return

                    if not tmpfile or not os.path.exists(tmpfile):
                        await status.edit(self._("download_error", error="unknown"))
                        return

                    size = os.path.getsize(tmpfile)
                    size_fmt = self._format_size(size)
                    if size > MAX_FILE_SIZE_HARD:
                        await status.edit(self._("too_big", size=size_fmt))
                        return

                    fname = "unknown"
                    try:
                        for attr in reply.document.attributes:
                            if hasattr(attr, "file_name") and attr.file_name:
                                fname = attr.file_name
                                break
                    except Exception:
                        pass

                    sha256 = await self._compute_sha256(tmpfile)
                    ftype = self._get_file_type(fname)

                    await status.edit(
                        self._("reanalyzing_file", sha256=sha256) if force
                        else self._("uploading", filename=fname[:80], size=size_fmt)
                    )

                    res = await self._scan_file(sha256, filepath=tmpfile, filename=fname, force=force)
                    if isinstance(res, dict) and res.get("error"):
                        await self._show_error(status, res["error"])
                        return

                    state = {
                        "page": 1,
                        "result": res,
                        "meta": {
                            "filename": fname[:120],
                            "size": size_fmt,
                            "filetype": ftype,
                            "sha256": sha256,
                        },
                    }
                    await status.delete()
                    await self._answer_inline(msg, state)
                    return

                reply_text = getattr(reply, "text", None) or getattr(reply, "raw_text", None)
                if reply_text:
                    url = self._extract_url(reply_text)
                    if url:
                        status = await utils.answer(
                            msg,
                            self._("rechecking_url" if force else "checking_url", url=url[:200]),
                        )
                        res = await self._scan_url(url, force=force)
                        if isinstance(res, dict) and res.get("error"):
                            await self._show_error(status, res["error"])
                            return

                        state = {
                            "page": 1,
                            "result": res,
                            "meta": {"url": url},
                        }
                        await status.delete()
                        await self._answer_inline(msg, state)
                        return

            await utils.answer(msg, self._("no_input"))

        except Exception as e:
            await utils.answer(msg, self._("api_error", error=str(e)[:120]))
        finally:
            if tmpfile and os.path.exists(tmpfile):
                try:
                    os.remove(tmpfile)
                except OSError:
                    pass