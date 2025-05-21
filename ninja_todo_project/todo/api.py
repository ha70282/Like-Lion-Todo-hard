from ninja import NinjaAPI, Schema
from ninja.security import APIKeyHeader
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from typing import List
from datetime import datetime
import uuid

from .models import Todo, ApiKey
from ninja.errors import HttpError

# --- 인증 클래스 정의 ---
class MyApiKeyAuth(APIKeyHeader):
    param_name = "Api-Key"
    header = "Authorization"

    def authenticate(self, request, key):
        try:
            api_key = ApiKey.objects.select_related('user').get(key=key)
            return api_key.user
        except ApiKey.DoesNotExist:
            return None

# --- API 인스턴스 생성 (인증 포함) ---
api = NinjaAPI(auth=[MyApiKeyAuth()])

# --- 스키마 정의 ---

class TodoSchema(Schema):
    id: int
    title: str
    completed: bool
    due_date: datetime

class TodoIn(Schema):
    title: str
    completed: bool
    due_date: datetime

class LoginIn(Schema):
    username: str
    password: str

class ApiKeyOut(Schema):
    api_key: uuid.UUID
class UserSummarySchema(Schema):
    id: int
    username: str
    email: str
    is_staff: bool

class UserProfileSchema(Schema):
    id: int
    username: str
    email: str
    first_name: str
    last_name: str
    date_joined: datetime
    api_key: uuid.UUID

class UserProfileUpdateSchema(Schema):
    email: str = None
    first_name: str = None
    last_name: str = None

class NewApiKeySchema(Schema):
    api_key: uuid.UUID

# --- 할 일 API 엔드포인트 ---

@api.get("/todos", response=List[TodoSchema])
def list_todos(request):
    todos = Todo.objects.filter(owner=request.auth).all()
    return todos

@api.get("/todos/{todo_id}", response=TodoSchema)
def get_todo(request, todo_id: int):
    todo = get_object_or_404(Todo, id=todo_id, owner=request.auth)
    return todo

@api.post("/todos", response=TodoSchema)
def create_todo(request, todo_in: TodoIn):
    todo = Todo.objects.create(**todo_in.dict(), owner=request.auth)
    return todo

@api.put("/todos/{todo_id}", response=TodoSchema)
def update_todo(request, todo_id: int, todo_in: TodoIn):
    todo = get_object_or_404(Todo, id=todo_id, owner=request.auth)
    for key, value in todo_in.dict().items():
        setattr(todo, key, value)
    todo.save()
    return todo

@api.delete("/todos/{todo_id}")
def delete_todo(request, todo_id: int):
    todo = get_object_or_404(Todo, id=todo_id, owner=request.auth)
    todo.delete()
    return {"success": True}

# --- 로그인 → API 키 발급 ---
@api.post("/token", response=ApiKeyOut, auth=None)
def generate_token(request, user_login: LoginIn):
    user = authenticate(request, username=user_login.username, password=user_login.password)
    if user:
        api_key, _ = ApiKey.objects.get_or_create(user=user)
        return ApiKeyOut(api_key=api_key.key)
    raise HttpError(status_code=401, message="Invalid username or password")

# --- 현재 사용자 정보 조회 ---
@api.get("/me", response=UserProfileSchema)
def get_my_profile(request):
    user = request.auth
    if not user:
        raise HttpError(401, "Unauthorized")

    api_key = ApiKey.objects.get(user=user)
    return UserProfileSchema(
        id=user.id,
        username=user.username,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        date_joined=user.date_joined,
        api_key=api_key.key
    )

# --- 현재 사용자 정보 수정 ---
@api.put("/me", response=UserProfileSchema)
def update_my_profile(request, payload: UserProfileUpdateSchema):
    user = request.auth
    if not user:
        raise HttpError(401, "Unauthorized")

    if payload.email is not None:
        user.email = payload.email
    if payload.first_name is not None:
        user.first_name = payload.first_name
    if payload.last_name is not None:
        user.last_name = payload.last_name
    user.save()

    api_key = ApiKey.objects.get(user=user)
    return UserProfileSchema(
        id=user.id,
        username=user.username,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        date_joined=user.date_joined,
        api_key=api_key.key
    )

# --- API 키 재발급 ---
@api.post("/me/regenerate-key", response=NewApiKeySchema)
def regenerate_api_key(request):
    user = request.auth
    if not user:
        raise HttpError(401, "Unauthorized")

    api_key = ApiKey.objects.get(user=user)
    api_key.key = uuid.uuid4()
    api_key.save()
    return NewApiKeySchema(api_key=api_key.key)
@api.get("/admin/users", response=List[UserSummarySchema])
def list_all_users(request):
    if not (request.auth and request.auth.is_staff):
        raise HttpError(status_code=403, message="Forbidden: Staff access required")

    users = User.objects.all()
    return [
        UserSummarySchema(
            id=u.id,
            username=u.username,
            email=u.email,
            is_staff=u.is_staff
        )
        for u in users
    ]

@api.get("/admin/users/{user_id}/todos", response=List[TodoSchema])
def get_user_todos(request, user_id: int):
    if not (request.auth and request.auth.is_staff):
        raise HttpError(status_code=403, message="Forbidden: Staff access required")

    target_user = get_object_or_404(User, id=user_id)
    todos = Todo.objects.filter(owner_id=target_user.id).all()
    return todos

