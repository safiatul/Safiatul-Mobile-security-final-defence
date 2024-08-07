from django.db import models
from django.contrib.auth.models import User
class MalwareDetection(models.Model):
    file_name = models.CharField(max_length=255)
    malware_name = models.CharField(max_length=255)
    detected_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE,null=True,blank=True)
    def __str__(self):
        return self.file_name

