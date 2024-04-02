import keyring
from keyring import backend

import google.auth


def is_valid(token):
    # stubbed
    return True
    google.auth


def get_token(username, password):
    # stubbed
    return ''


class GoogleAuthBackend(backend.KeyringBackend):
    priority = 10  # type: ignore
    """
    Higher priority than typical recommended backends.
    """

    ext = ' (token)'
    auth_service_name = 'Google Auth'

    def handle(self, service):
        """
        Should this backend resolve tokens for this service?
        """
        return service.startswith('https://gcp-pypi') and not service.endswith(self.ext)

    def get_password(self, service, username):
        if not self.handle(service):
            return

        # store the token in a name _not_ handled by this backend
        token_service = service + self.ext
        assert not self.handle(token_service)

        # first check if there's already a valid token stored
        token = keyring.get_password(token_service, username)
        if token and is_valid(token):
            return token

        # get the user's password to resolve to a token. User
        # should have set this password. This service name must also
        # not be handled by this backend.
        pw = keyring.get_password(self.auth_service_name, username)
        assert not self.handle(self.auth_service_name)
        token = get_token(username, pw)
        keyring.set_password(token_service, username, token)
        return token

    def set_password(self, service, username, password):
        raise NotImplementedError()

    def delete_password(self, service, username):
        raise NotImplementedError()

    def get_credential(self, service, username):
        return
