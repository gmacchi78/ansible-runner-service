
from flask import request
import threading
import logging

from .base import BaseResource
from .utils import log_request
from runner_service.utils import SecureContext, InvalidUserException
from ..services.utils import APIResponse

logger = logging.getLogger(__name__)
file_mutex = threading.Lock()



class ChangePassword(BaseResource):
    """ Changes user's passwords """

    @log_request(logger)
    def post(self, user_name):
        """
        POST {user_name, old_passwd, new_passwd}

        
        Changes the user's password. The new password must have at least 10 characters.

        ```
        $ curl -k -i --key ./client.key --cert ./client.crt  -d 'old_passwd=pass&new_passwd=password123' https://localhost:5001/api/v1/user/admin/password -X POST
        < HTTP/1.1 200 OK
        < Server: Werkzeug/2.2.2 Python/3.8.15
        < Date: Wed, 21 Dec 2022 13:45:08 GMT
        < Content-Type: application/json
        < Content-Length: 70
        < Connection: close
        {
            "status": "OK",
            "msg": "Password changed",
            "data": {}
        }

        ```
        """
        old_passwd = request.form.get('old_passwd', "")
        new_passwd = request.form.get('new_passwd', "")
        
        response = APIResponse()

        if '' in [new_passwd, old_passwd ]:
            response.status, response.msg = "BAD_REQUEST", "Invalid arguments"
        elif len(new_passwd)<10:
            response.status, response.msg ="BAD_REQUEST", "Password must be at least 10 characters"
        else:
            try:
                user = SecureContext.get_or_create().update_password(
                    user_name=user_name, old_passwd=old_passwd, new_passwd=new_passwd)
                if user.expired:
                    response.status, response.msg = "FAILED","Server error" 
                else:
                    response.status, response.msg = "OK", "Password changed" 
            except InvalidUserException:
                response.status, response.msg = "FAILED", f"Invalid old password for user {user_name}"

        return response.__dict__, self.state_to_http[response.status]
