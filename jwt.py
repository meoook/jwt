import base64
import hmac
import json
from datetime import datetime


class JwtCoder:
    __ALGORITHM = 'sha256'
    __HEADER_BS64 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9'  # equal to {"typ":"JWT","alg":"HS256"}
    __DEFAULT_MAX_LEN = 4096  # If JWT used in Get request - URI limit is 1024
    __DEFAULT_TS_NAME = 'timestamp'
    __DEFAULT_VALID_TIME = 86400  # One day

    def __init__(self, secret_key: str, len_check: int = None, ts_name: str = None, valid_time: int = None):
        """
            Params (if not set - used defaults):
              *Secret key* must be set to create check signature_bs64
              *Len check* max len of token (set 0 for no check)
              *Timestamp name* field name in payload to check with *valid_time* (set '' for no check)
              *Valid time* while token is valid from creating (if *ts_name* not set - no check)
        """
        assert secret_key and isinstance(secret_key, str), 'Secret key must be set'
        self.__secret_key: bytes = secret_key.encode()
        self.__max_len: int = len_check if len_check and isinstance(len_check, int) else self.__DEFAULT_MAX_LEN
        self.__valid_time: int = valid_time if valid_time and isinstance(valid_time, int) else self.__DEFAULT_VALID_TIME
        self.__ts_name: str = ts_name if ts_name and isinstance(ts_name, str) else self.__DEFAULT_TS_NAME

    def encode(self, payload: dict[str, any]) -> str:
        """ Return JWT from payload as dict if chek length passed """
        assert payload and isinstance(payload, dict), 'Parameter payload must be type - dict'
        _payload_b: bytes = json.dumps(payload, separators=(',', ':')).encode()
        _payload_bs64: str = base64.urlsafe_b64encode(_payload_b).decode().rstrip('=')

        _signature_b: bytes = self.__create_check_signature(self.__HEADER_BS64, _payload_bs64)
        _signature_bs64: str = base64.urlsafe_b64encode(_signature_b).decode().rstrip("=")

        jwt = f'{self.__HEADER_BS64}.{_payload_bs64}.{_signature_bs64}'
        if self.__max_len:
            assert len(jwt) <= self.__max_len, f'Return JWT key too long {self.__max_len}'
        return jwt

    def decode(self, token: str) -> dict[str, any]:
        """ Validate token and return its payload data if valid """
        _jwt_parts = token.split('.')
        return self.__decode(*_jwt_parts) if len(_jwt_parts) == 3 else {}

    def __decode(self, header_bs64: str, payload_bs64: str, signature_bs64: str) -> dict[str, any]:
        """ Validate signature and time after created. Return payload dict if valid. """
        # Safe decode incoming signature
        _signature_income: bytes = self.__bs64decode_with_fix_padding(signature_bs64)
        # Create signature by incoming data and secret key
        _signature_check: bytes = self.__create_check_signature(header_bs64, payload_bs64)
        # Validate signature
        if _signature_income != _signature_check:
            return {}
        # Get payload as dict
        _payload_dict = self.__get_data(payload_bs64)
        # Validate time if timestamp lookup field set
        if self.__ts_name:
            try:
                _created_date = _payload_dict[self.__ts_name]
            except KeyError:  # FIXME: return {} or raise error ?
                # raise KeyError(f'Field name `{self.__ts_name}` not found in payload to validate time')
                return {}
            _check_date = datetime.timestamp(datetime.now()) - self.__valid_time
            if _created_date < _check_date:
                return {}
        return _payload_dict

    def __get_data(self, payload: str) -> dict[str, any]:
        """ Get payload_bs64 from JWT payload_bs64 """
        _data = self.__bs64decode_with_fix_padding(payload)
        return json.loads(_data)

    def __create_check_signature(self, header_bs64: str, payload_bs64: str) -> bytes:
        """ Create signature_bs64 with income payload_bs64 by secret key """
        _message = f'{header_bs64}.{payload_bs64}'.encode()
        _context = hmac.new(self.__secret_key, _message, self.__ALGORITHM)
        return _context.digest()

    @staticmethod
    def __bs64decode_with_fix_padding(value: str) -> bytes:
        """ JWT token cut '='. This method add '=' to the end row to fix bytes length """
        _val_binary = value.encode()
        _val_binary += b"=" * ((4 - len(_val_binary) % 4) % 4)
        _signature = base64.urlsafe_b64decode(_val_binary)
        return _signature
