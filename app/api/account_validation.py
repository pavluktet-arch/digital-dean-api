from typing import Callable
from fastapi import Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

class SensitiveRoute(APIRoute):
    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            try:
                return await original_route_handler(request)
            except RequestValidationError as exc:
                sanitized_errors = []
                for error in exc.errors():
                    err_dict = dict(error)
                    err_dict.pop("input", None)
                    err_dict.pop("ctx", None)
                    sanitized_errors.append(err_dict)
                return JSONResponse(
                    status_code=422,
                    content={"detail": sanitized_errors},
                )

        return custom_route_handler