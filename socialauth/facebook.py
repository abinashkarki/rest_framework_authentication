import facebook

class Facebook:
    '''facebook class to fetch the user info and return it'''
    @staticmethod
    def validate(auth_token):
        try:
            graph = facebook.GraphAPI(access_token=auth_token)
            profile = graph.request('/me?fields=name, email')
            return profile
        except:
            return "the token is invalid or expired"