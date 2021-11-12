from django.db import models
from django.utils.translation import gettext_lazy as _

def upload_to(instance, filename):
    return 'posts/{filename}'.format(filename=filename)

class application(models.Model):
    # appid = models.AutoField(default=00, primary_key=True)
    name = models.CharField(max_length=100)
    logo = models.ImageField(_("images"), upload_to=upload_to)