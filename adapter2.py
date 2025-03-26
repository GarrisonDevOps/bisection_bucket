
    def build_response(
        self,
        request: PreparedRequest,
        response: HTTPResponse,
        from_cache: bool = False,
        cacheable_methods: Collection[str] | None = None,
    ) -> Response:
        """
        Build a response by making a request or using the cache.

        This will end up calling send and returning a potentially
        cached response
        """
        cacheable = cacheable_methods or self.cacheable_methods
        if not from_cache and request.method in cacheable:
            # Check for any heuristics that might update headers
            # before trying to cache.
            if self.heuristic:
                response = self.heuristic.apply(response)

            # apply any expiration heuristics
            if response.status == 304:
                # We must have sent an ETag request. This could mean
                # that we've been expired already or that we simply
                # have an etag. In either case, we want to try and
                # update the cache if that is the case.
                cached_response = self.controller.update_cached_response(
                    request, response
                )

                if cached_response is not response:
                    from_cache = True

                # We are done with the server response, read a
                # possible response body (compliant servers will
                # not return one, but we cannot be 100% sure) and
                # release the connection back to the pool.
                response.read(decode_content=False)
                response.release_conn()

                response = cached_response

            # We always cache the 301 responses
            elif int(response.status) in PERMANENT_REDIRECT_STATUSES:
                self.controller.cache_response(request, response)
            else:
                # Wrap the response file with a wrapper that will cache the
                #   response when the stream has been consumed.
                response._fp = CallbackFileWrapper(  # type: ignore[attr-defined]
                    response._fp,  # type: ignore[attr-defined]
                    functools.partial(
                        self.controller.cache_response, request, response
                    ),
                )
                if response.chunked:
                    super_update_chunk_length = response._update_chunk_length  # type: ignore[attr-defined]

                    def _update_chunk_length(self: HTTPResponse) -> None:
                        super_update_chunk_length()
                        if self.chunk_left == 0:
                            self._fp._close()  # type: ignore[attr-defined]

                    response._update_chunk_length = types.MethodType(  # type: ignore[attr-defined]
                        _update_chunk_length, response
                    )

        resp: Response = super().build_response(request, response)  # type: ignore[no-untyped-call]

        # See if we should invalidate the cache.
        if request.method in self.invalidating_methods and resp.ok:
            assert request.url is not None
            cache_url = self.controller.cache_url(request.url)
            self.cache.delete(cache_url)

        # Give the request a from_cache attr to let people use it
        resp.from_cache = from_cache  # type: ignore[attr-defined]

        return resp

    def close(self) -> None:
        self.cache.close()
        super().close()  # type: ignore[no-untyped-call]