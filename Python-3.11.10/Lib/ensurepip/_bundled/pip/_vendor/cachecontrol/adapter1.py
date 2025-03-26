# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import functools
import types
import zlib
from typing import TYPE_CHECKING, Any, Collection, Mapping

from pip._vendor.requests.adapters import HTTPAdapter

from pip._vendor.cachecontrol.cache import DictCache
from pip._vendor.cachecontrol.controller import PERMANENT_REDIRECT_STATUSES, CacheController
from pip._vendor.cachecontrol.filewrapper import CallbackFileWrapper

if TYPE_CHECKING:
    from pip._vendor.requests import PreparedRequest, Response
    from pip._vendor.urllib3 import HTTPResponse

    from pip._vendor.cachecontrol.cache import BaseCache
    from pip._vendor.cachecontrol.heuristics import BaseHeuristic
    from pip._vendor.cachecontrol.serialize import Serializer


class CacheControlAdapter(HTTPAdapter):
    invalidating_methods = {"PUT", "PATCH", "DELETE"}

    def __init__(
        self,
        cache: BaseCache | None = None,
        cache_etags: bool = True,
        controller_class: type[CacheController] | None = None,
        serializer: Serializer | None = None,
        heuristic: BaseHeuristic | None = None,
        cacheable_methods: Collection[str] | None = None,
        *args: Any,
        **kw: Any,
    ) -> None:
        super().__init__(*args, **kw)
        self.cache = DictCache() if cache is None else cache
        self.heuristic = heuristic
        self.cacheable_methods = cacheable_methods or ("GET",)

        controller_factory = controller_class or CacheController
        self.controller = controller_factory(
            self.cache, cache_etags=cache_etags, serializer=serializer
        )

    def send(
        self,
        request: PreparedRequest,
        stream: bool = False,
        timeout: None | float | tuple[float, float] | tuple[float, None] = None,
        verify: bool | str = True,
        cert: (None | bytes | str | tuple[bytes | str, bytes | str]) = None,
        proxies: Mapping[str, str] | None = None,
        cacheable_methods: Collection[str] | None = None,
    ) -> Response:
        """
        Send a request. Use the request information to see if it
        exists in the cache and cache the response if we need to and can.
        """
        cacheable = cacheable_methods or self.cacheable_methods
        if request.method in cacheable:
            try:
                cached_response = self.controller.cached_request(request)
            except zlib.error:
                cached_response = None
            if cached_response:
                return self.build_response(request, cached_response, from_cache=True)

            # check for etags and add headers if appropriate
            request.headers.update(self.controller.conditional_headers(request))

        resp = super().send(request, stream, timeout, verify, cert, proxies)

        return resp