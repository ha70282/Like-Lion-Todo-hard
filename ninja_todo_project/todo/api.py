# todo/api.py 에 추가

from ninja import NinjaAPI, Schema # Schema 임포트
from typing import List # 리스트 타입을 명시하기 위해 임포트
from .models import Todo # 우리의 Todo 모델 임포트
from django.shortcuts import get_object_or_404 # 특정 객체 가져올 때 유용
from datetime import datetime

api = NinjaAPI()

# --- Schema 정의 ---
# API 응답/요청 데이터의 형식을 정의합니다.
class TodoSchema(Schema):
    id: int # 모델의 id 필드
    title: str # 모델의 title 필드
    completed: bool # 모델의 completed 필드
    due_date: datetime         
    

# --- GET Endpoints ---

# 모든 할 일 목록 가져오기
@api.get("/todos", response=List[TodoSchema]) # 응답은 TodoSchema의 리스트 형태
def list_todos(request):
    todos = Todo.objects.all() # 모든 Todo 객체 가져오기
    # QuerySet은 바로 JSON이 안되므로, Schema를 통해 변환해서 넘겨줍니다.
    return todos # django-ninja가 QuerySet을 받으면 자동으로 Schema 리스트로 변환 시도

# 특정 할 일 하나 가져오기 (ID로 구분)
# URL 경로에 {todo_id: int} 로 경로 파라미터를 받습니다. int 타입으로 자동 검증
@api.get("/todos/{todo_id}", response=TodoSchema) # 응답은 TodoSchema 하나
def get_todo(request, todo_id: int):
    # todo_id를 사용하여 특정 Todo 객체 찾기
    # 없으면 404 Not Found 에러를 자동으로 발생시킵니다.
    todo = get_object_or_404(Todo, id=todo_id)
    return todo # django-ninja가 모델 객체를 받으면 자동으로 Schema로 변환 시도


# todo/api.py 에 추가

# Input Schema - 데이터 생성/수정 시 요청 본문의 형식을 정의합니다.
class TodoIn(Schema):
    title: str # 제목 (필수)
    completed: bool = False # 완료 여부
    due_date: datetime 
    

# --- POST Endpoint (할 일 생성) ---
# 요청 본문은 TodoIn 스키마 형태로 받을 것을 명시
@api.post("/todos", response=TodoSchema) # 응답은 생성된 Todo 객체의 Schema 형태
def create_todo(request, todo_in: TodoIn):
    # todo_in 객체에는 요청 본문에서 파싱된 데이터가 들어있습니다.
    due_date=todo_in.due_date
    # todo_in.dict() 로 딕셔너리 형태로 만들어서 모델 생성에 사용
    todo = Todo.objects.create(**todo_in.dict())
    return todo # 생성된 객체를 반환하면 django-ninja가 TodoSchema로 변환
    
# todo/api.py 에 추가

# --- PUT/PATCH Endpoint (할 일 수정) ---
# {todo_id: int} 로 수정할 할 일 지정, todo_in: TodoIn 으로 수정할 내용 받기
@api.put("/todos/{todo_id}", response=TodoSchema)
def update_todo(request, todo_id: int, todo_in: TodoIn):
    todo = get_object_or_404(Todo, id=todo_id) # 수정할 객체 찾기
    todo.due_date = todo_in.due_date
    # todo_in.dict() 의 내용을 todo 객체에 업데이트
    for key, value in todo_in.dict().items():
        setattr(todo, key, value) # 객체의 속성(key)에 값(value) 설정
    todo.save() # 데이터베이스에 저장
    return todo # 수정된 객체를 반환
# todo/api.py 에 추가

# ... 기존 임포트들

# ... TodoSchema, TodoIn 정의

# --- DELETE Endpoint (할 일 삭제) ---
# 삭제 성공 시 204 No Content 상태 코드를 반환합니다.
@api.delete("/todos/{todo_id}")
def delete_todo(request, todo_id: int):
    todo = get_object_or_404(Todo, id=todo_id) # 삭제할 객체 찾기
    todo.delete() # 삭제!