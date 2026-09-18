"""전용 영속 profile을 소유하는 직렬화된 Playwright Worker입니다."""

from __future__ import annotations

from concurrent.futures import CancelledError
from threading import Lock
from typing import TYPE_CHECKING, Final, Self, final
from uuid import UUID

from anyio.from_thread import BlockingPortal, start_blocking_portal
from playwright.async_api import BrowserContext, Error, Page, Playwright, async_playwright
from pydantic import JsonValue, TypeAdapter

from hermes_windows_bridge.worker import browser_safety as safety

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path
    from types import TracebackType

_STORAGE_VALUES: Final[TypeAdapter[tuple[str, ...]]] = TypeAdapter(tuple[str, ...])


@final
class BrowserWorker:
    """한 전용 Playwright context의 수명과 순차 실행 thread를 소유합니다."""

    def __init__(
        self,
        *,
        profile_dir: Path,
        headless: bool,
        max_output_bytes: int,
        action_timeout_ms: int = 5_000,
        navigation_timeout_ms: int = 15_000,
    ) -> None:
        """전용 profile 경로와 반환 byte 상한을 고정합니다."""
        self._profile_dir = safety.validated_profile_dir(profile_dir)
        if action_timeout_ms <= 0 or navigation_timeout_ms <= 0:
            raise safety.BrowserWorkerError("invalid_timeout")  # noqa: EM101
        self._headless, self._max_output_bytes = headless, max_output_bytes
        self._action_ms, self._navigation_ms = action_timeout_ms, navigation_timeout_ms
        self._submission_lock = Lock()
        self._active_lock = Lock()
        self._active_operation: UUID | None = None
        self._active_cancel: Callable[[], bool] | None = None
        self._profile_guard: safety.BrowserProfileGuard | None = None
        self._portal_context = start_blocking_portal(name="hermes-browser")
        self._portal: BlockingPortal = self._portal_context.__enter__()
        try:
            self._profile_guard = safety.BrowserProfileGuard(self._profile_dir)
        except OSError, safety.BrowserWorkerError:
            _ = self._portal_context.__exit__(None, None, None)
            raise
        self._playwright: Playwright | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None

    def __enter__(self) -> Self:
        """Context 종료 시 browser thread까지 정리하도록 자신을 반환합니다."""
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """예외 여부와 무관하게 persistent context와 thread를 종료합니다."""
        try:
            _ = self.close()
        finally:
            _ = self._portal_context.__exit__(exception_type, exception, traceback)

    def status(self, operation_id: UUID | None = None) -> safety.BrowserStatus:
        """직렬 실행 thread에서 browser 상태를 읽습니다."""
        return self._run(operation_id, self._status)

    def open(self, url: str = "about:blank", operation_id: UUID | None = None) -> safety.BrowserStatus:  # noqa: E501
        """Persistent context를 열고 지정 URL로 이동합니다."""
        return self._run(operation_id, lambda: self._open(url))

    def snapshot(self, operation_id: UUID | None = None) -> safety.BrowserContentResult:
        """ARIA/DOM semantic snapshot을 수집하고 session 비밀을 제거합니다."""
        return self._run(operation_id, lambda: self._extract("body", semantic=True))

    def click(self, selector: str, operation_id: UUID | None = None) -> safety.BrowserStatus:
        """Strict Playwright locator를 click합니다."""
        return self._run(operation_id, lambda: self._act(selector, None))

    def type_text(
        self, selector: str, text: str, operation_id: UUID | None = None
    ) -> safety.BrowserStatus:
        """Strict Playwright locator를 지정 text로 채웁니다."""
        return self._run(operation_id, lambda: self._act(selector, text))

    def extract(
        self, selector: str, operation_id: UUID | None = None
    ) -> safety.BrowserContentResult:
        """Selector의 visible text를 bounded untrusted data로 반환합니다."""
        return self._run(operation_id, lambda: self._extract(selector, semantic=False))

    def evaluate(
        self, expression: str, operation_id: UUID | None = None
    ) -> safety.BrowserEvaluationResult:
        """Caller JavaScript 없이 predefined read-only query만 수행합니다."""
        return self._run(operation_id, lambda: self._evaluate(expression))

    def cancel(self, operation_id: UUID) -> bool:
        """일치하는 진행 중 operation만 취소합니다."""
        with self._active_lock:
            return (
                self._active_operation == operation_id
                and self._active_cancel is not None
                and self._active_cancel()
            )

    def close(self, operation_id: UUID | None = None) -> safety.BrowserStatus:
        """Persistent context를 닫되 Worker는 재사용 가능하게 유지합니다."""
        with self._active_lock:
            if self._active_cancel is not None:
                _ = self._active_cancel()
        return self._run(operation_id, self._close)

    def _run[ResultT](
        self, operation_id: UUID | None, action: Callable[[], Awaitable[ResultT]]
    ) -> ResultT:
        correlated_id = operation_id or UUID(int=0)
        with self._submission_lock:
            future = self._portal.start_task_soon(action)
            with self._active_lock:
                self._active_operation = correlated_id
                self._active_cancel = future.cancel
            try:
                return future.result()
            except CancelledError as error:
                raise safety.BrowserWorkerError("operation_cancelled") from error  # noqa: EM101
            finally:
                with self._active_lock:
                    self._active_operation = None
                    self._active_cancel = None

    async def _status(self) -> safety.BrowserStatus:
        page = self._page
        url = None
        if page is not None and not page.is_closed():
            url = safety.safe_browser_url(page.url)
        return safety.BrowserStatus(self._context is not None, url, self._profile_dir)

    async def _ensure_page(self) -> Page:
        context = self._context
        if context is None:
            raise safety.BrowserWorkerError("browser_not_open")  # noqa: EM101
        page = self._page
        if page is None or page.is_closed():
            page = await context.new_page()
            self._page = page
        return page

    async def _open(self, url: str) -> safety.BrowserStatus:
        if self._context is None:
            if self._profile_guard is None:
                self._profile_guard = safety.BrowserProfileGuard(self._profile_dir)
            playwright: Playwright | None = None
            try:
                playwright = await async_playwright().start()
                context = await playwright.chromium.launch_persistent_context(
                    self._profile_dir,
                    headless=self._headless,
                )
            except Error, OSError:
                try:
                    if playwright is not None:
                        await playwright.stop()
                finally:
                    self._release_profile_guard()
                raise
            context.set_default_timeout(self._action_ms)
            context.set_default_navigation_timeout(self._navigation_ms)
            self._playwright = playwright
            self._context = context
            self._page = context.pages[0] if context.pages else await context.new_page()
        page = await self._ensure_page()
        _ = await page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=self._navigation_ms,
        )
        return safety.BrowserStatus(
            running=True, url=safety.safe_browser_url(page.url), profile_dir=self._profile_dir
        )

    async def _act(self, selector: str, text: str | None) -> safety.BrowserStatus:
        page = await self._ensure_page()
        locator = page.locator(selector)
        if text is None:
            await locator.click(timeout=self._action_ms)
        else:
            await locator.fill(text, timeout=self._action_ms)
        return safety.BrowserStatus(
            running=True, url=safety.safe_browser_url(page.url), profile_dir=self._profile_dir
        )

    async def _extract(self, selector: str, *, semantic: bool) -> safety.BrowserContentResult:
        page = await self._ensure_page()
        locator = page.locator(selector)
        content = (
            await locator.aria_snapshot(mode="ai", timeout=self._action_ms)
            if semantic
            else await locator.inner_text(timeout=self._action_ms)
        )
        return await self._content_result(page, content)

    async def _evaluate(self, expression: str) -> safety.BrowserEvaluationResult:
        page = await self._ensure_page()
        query = safety.parse_browser_read_query(expression)
        async def read_url() -> str:
            return safety.safe_browser_url(page.url)

        readers: dict[safety.BrowserReadQuery, Callable[[], Awaitable[str]]] = {
            safety.BrowserReadQuery.TITLE: page.title,
            safety.BrowserReadQuery.URL: read_url,
            safety.BrowserReadQuery.LOCATION: read_url,
            safety.BrowserReadQuery.BODY_TEXT: lambda: page.locator("body").inner_text(
                timeout=self._action_ms
            ),
        }
        value: JsonValue = await readers[query]()
        if len(str(value).encode("utf-8")) > self._max_output_bytes:
            raise safety.BrowserWorkerError("output_limit")  # noqa: EM101
        redacted = safety.redact_browser_json(value, await self._secret_values(page))
        return safety.BrowserEvaluationResult(safety.safe_browser_url(page.url), redacted)

    async def _content_result(self, page: Page, content: str) -> safety.BrowserContentResult:
        redacted = safety.redact_browser_text(content, await self._secret_values(page))
        bounded, truncated = safety.bounded_utf8(redacted, self._max_output_bytes)
        return safety.BrowserContentResult(safety.safe_browser_url(page.url), bounded, truncated)

    async def _secret_values(self, page: Page) -> frozenset[str]:
        cookie_values = {
            value
            for cookie in await page.context.cookies()
            if (value := cookie.get("value")) is not None
        }
        password_values = {
            await locator.input_value(timeout=self._action_ms)
            for locator in await page.locator("input[type=password]").all()
        }
        raw_storage = TypeAdapter(str).validate_python(
            await page.evaluate(
                """() => location.origin === "null"
                    ? "[]"
                    : JSON.stringify([...Object.values(localStorage),
                                      ...Object.values(sessionStorage)])"""
            )
        )
        storage_values = _STORAGE_VALUES.validate_json(raw_storage)
        return frozenset(
            value for value in (*cookie_values, *password_values, *storage_values) if value
        )

    async def _close(self) -> safety.BrowserStatus:
        context, playwright = self._context, self._playwright
        self._page = None
        self._context = None
        self._playwright = None
        try:
            if context is not None:
                await context.close(reason="hermes_browser_close")
        finally:
            try:
                if playwright is not None:
                    await playwright.stop()
            finally:
                self._release_profile_guard()
        return safety.BrowserStatus(running=False, url=None, profile_dir=self._profile_dir)

    def _release_profile_guard(self) -> None:
        guard, self._profile_guard = self._profile_guard, None
        if guard is not None:
            guard.close()
