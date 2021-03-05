from flask_login import UserMixin

class User(UserMixin):
    def get_id(self):
        return 1
