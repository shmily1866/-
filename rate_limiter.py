import asyncio
import logging
from typing import Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from . import crud
from .scraper_manager import ScraperManager
from .timezone import get_now

logger = logging.getLogger(__name__)

class RateLimitExceededError(Exception):
    def __init__(self, message, retry_after_seconds):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds

class RateLimiter:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession], scraper_manager: ScraperManager):
        self._session_factory = session_factory
        self._scraper_manager = scraper_manager
        self.logger = logging.getLogger(self.__class__.__name__)

        # ======= LOCAL BYPASS PATCH START =======
        self.enabled: bool = False
        self.global_limit: int = 0
        self.global_period_seconds: int = 3600
        self._verification_failed: bool = False
        self.logger.warning(
            "Local patch: RateLimiter bypass enabled — all limits are disabled, config files will NOT be read."
        )
        # ======= LOCAL BYPASS PATCH END =======

    async def _get_provider_quota(self, provider_name: str) -> Optional[int]:
        try:
            scraper = self._scraper_manager.get_scraper(provider_name)
            quota = getattr(scraper, 'rate_limit_quota', None)
            if quota is not None and quota > 0:
                return quota
        except (ValueError, AttributeError):
            pass
        return None

    def _get_global_limit(self) -> Tuple[int, int]:
        if not self.enabled:
            return 0, 3600
        return self.global_limit, self.global_period_seconds

    async def check(self, provider_name: str):
        if self._verification_failed:
            msg = "配置验证失败，所有请求已被安全阻止。"
            raise RateLimitExceededError(msg, retry_after_seconds=3600)

        global_limit, period_seconds = self._get_global_limit()
        if global_limit <= 0:
            return

        async with self._session_factory() as session:
            global_state = await crud.get_or_create_rate_limit_state(session, "__global__")
            provider_state = await crud.get_or_create_rate_limit_state(session, provider_name)

            now = get_now()
            time_since_reset = now - global_state.lastResetTime

            if time_since_reset.total_seconds() >= period_seconds:
                self.logger.info(f"全局速率限制周期已过，正在重置所有计数器。")
                await crud.reset_all_rate_limit_states(session)
                await session.commit()
                await session.refresh(global_state)
                await session.refresh(provider_state)
                time_since_reset = now - global_state.lastResetTime

            if global_state.requestCount >= global_limit:
                retry_after = period_seconds - time_since_reset.total_seconds()
                msg = f"已达到全局速率限制 ({global_state.requestCount}/{global_limit})。"
                self.logger.warning(msg)
                raise RateLimitExceededError(msg, retry_after_seconds=max(0, retry_after))

            provider_quota = await self._get_provider_quota(provider_name)
            if provider_quota is not None and provider_state.requestCount >= provider_quota:
                retry_after = period_seconds - time_since_reset.total_seconds()
                msg = f"已达到源 '{provider_name}' 的特定配额 ({provider_state.requestCount}/{provider_quota})。"
                self.logger.warning(msg)
                raise RateLimitExceededError(msg, retry_after_seconds=max(0, retry_after))

    async def increment(self, provider_name: str):
        global_limit, _ = self._get_global_limit()
        if global_limit <= 0:
            return

        async with self._session_factory() as session:
            await crud.increment_rate_limit_count(session, "__global__")
            await crud.increment_rate_limit_count(session, provider_name)
            await session.commit()
            self.logger.debug(f"已为 '__global__' 和 '{provider_name}' 增加下载流控计数。")

