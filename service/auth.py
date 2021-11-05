import calendar
import datetime
import jwt
from constants import JWT_SECRET, JWT_ALGORITHM
from service.user import UserService

class AuthService():
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def generate_tokens(self, username, password, is_refresh=False):
        user = self.user_service.get_by_username(username)

        if user is None:
            raise Exception()

        if not is_refresh:
            if not self.user_service.compare_passwords(user.password, password):
                raise Exception()

            data = {
                'username': user.username,
                'role': user.role
            }

            min30 = datetime.datetime.now() + datetime.timedelta(minutes=30)
            data['exp'] = calendar.timegm(min30.timetuple())
            access_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)

            days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
            data['exp'] = calendar.timegm(days130.timetuple())
            refresh_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)

        else:
            data = jwt.decode(password, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            username = data.get('username')
            user = self.user_service.get_by_username(username)

            if user is None:
                raise Exception()

            data = {
                'username': user.username,
                'role': user.role
            }

            min30 = datetime.datetime.now() + datetime.timedelta(minutes=30)
            data['exp'] = calendar.timegm(min30.timetuple())
            access_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)

        return {'access_token': access_token, 'refresh_token': refresh_token}
