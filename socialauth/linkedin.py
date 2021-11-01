from linkedin import linkedin
from linkedin import server

class Linkedin:
    @staticmethod
    def validate(oauth2_access_token):
        application = linkedin.LinkedInApplication(token=oauth2_access_token)
        # profile = application.get_profile()
        profile = application.get_profile(selectors=['id', 'first-name'])
        return profile
        # try:  
        #     application = linkedin.LinkedInApplication(token=oauth2_access_token)
        #     profile = application.get_profile()
        #     print(profile)
        #     return profile
            
        # except:
        #     return "the token is invalid"
