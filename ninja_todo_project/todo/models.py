# todo/models.py

from django.db import models
from django.contrib.auth import get_user_model # User 모델을 안전하게 가져오는 함수

User = get_user_model() # Django의 User 모델 가져오기

class Todo(models.Model):
    # owner 필드 추가: User 모델과 1:N 관계
    # on_delete=models.CASCADE: User가 삭제되면 관련된 Todo도 함께 삭제
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='todos')

    title = models.CharField(max_length=200)
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # 어떤 사용자의 할 일인지 표시되도록 __str__ 수정
        return f"{self.owner.username}'s Todo: {self.title}"

from django.contrib import admin
admin.site.register(Todo)
import uuid # 고유한 Key 생성을 위해 임포트

class ApiKey(models.Model):
    # user 필드: User 모델과 1:1 관계 (User 삭제 시 ApiKey도 삭제)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # key 필드: API Key 값 (고유해야 하며, 수정 불가능하게)
    key = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}'s API Key"

from django.contrib import admin
admin.site.register(ApiKey)