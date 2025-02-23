from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
    status,
    HTTPException,
    Request,
    Query,
    Header,
    Depends,
)
from fastapi.encoders import jsonable_encoder as pydantic_decoder
from core.tools import manager, parser, encoder, decoder, database
from fastapi_csrf_protect import CsrfProtect
from fastapi.responses import JSONResponse
from api.wsmanager import Room, Connection
from api.wshandler import WsHandler
from schemes.room import RoomAuth
from core.config import settings
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class CsrfSettings(BaseModel):
    secret_key: str = settings.CSRF_SECRET_KEY


@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()


@router.post("/{name}/auth")
async def room_password_auth(
    name: str,
    auth: RoomAuth,
    x_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
) -> JSONResponse or HTTPException:
    msg_key = decoder.get_key(authorization) if authorization else ""
    data = pydantic_decoder(auth)
    username, password = data["username"], data["password"]
    hased_name = parser.parse_link_hash(name)  # TODO hashed
    room = database.get_room_by_name(hased_name)
    print(username, password)
    if decoder.verify_hash(password, room.password):
        print("Password verified")  # ADDED
        if x_token: # TODO А зачем нам этот x-token
            print("Verifying token")  # ADDED
            if decoder.verify_hash(username, x_token):
                print("Token verified")  # ADDED
                user = database.get_user_by_name(username, room.id)
            else:
                print("Invalid token")  # ADDED
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"Status": "Invalid username or password KEK"},
                )
        else:
            print("Creating user")  # ADDED
            user = database.create_user(username, False, room)
        sessionCookie = encoder.encode_session(
            hased_name, user.id, room.id, user.admin, msg_key
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"User": username},
            headers={
                "Content-Type": "application/json",
                "Cookie": f"session={sessionCookie}",
                "X-Token": encoder.hash_text(username),
            },
        )
    print("POLNAYA JOPA")  # ADDED
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"Error": "Invalid username or password"},
        headers={"Content-Type": "application/json", "WWW-Authenticate": "Bearer"},
    )


@router.get("/{name}")
async def room(
    name: str,
    authorization: Optional[str] = Header(None),
    csrf_protect: CsrfProtect = Depends(),
) -> JSONResponse or HTTPException:
    print("Room request")  # ADDED
    hashed_name, room, user = parser.get_room_data(name, authorization)
    if decoder.verify_session(hashed_name, authorization, user.status):
        print("Session verified")  # ADDED
        enc_messages, messages = database.get_all_messages(room), []
        for message in enc_messages:
            messages.append(
                {
                    "Message": message.data,
                    "Created_at": parser.parse_msg_time(message.created_at),
                    "Username": message.user_name,
                }
            )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "User": user.name,
                "Messages": messages,
                "Users": parser.parse_room_users(list(room.users)),
            },
            headers={
                "Content-Type": "application/json",
                "Connection": "keep-alive",
                "X-CSRF-Token": csrf_protect.generate_csrf_tokens()[1],
                "X-Token": encoder.hash_text(user.name),
            },
        )
    print("Session verification failed!")  # ADDED
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"Status": "Invalid session"},
        headers={
            "Content-Type": "application/json",
            "WWW-Authenticate": "Bearer",
        },
    )


@router.delete("/{name}")
async def delete_room(
    request: Request,
    name: str,
    authorization: Optional[str] = Header(None),
    csrf_protect: CsrfProtect = Depends(),
) -> JSONResponse or HTTPException:
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    hashed_name, room, user = parser.get_room_data(name, authorization)
    if decoder.verify_session(hashed_name, authorization, user.status, True):
        database.delete_room(room)
        return JSONResponse(
            status_code=status.HTTP_204_NO_CONTENT,
            content={"Status": "Room has been deleted"},
            headers={
                "Location": "/",
            },
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail={"User not admin"}
    )


@router.websocket("/{name}")
async def websocket_endpoint(
    websocket: WebSocket, name: str, session: Optional[str] = Query(None)
) -> None:
    print(f"WebSocket connection attempt: name={name}, session={session}")  # ADDED
    hashed_name, room_obj, user = parser.get_room_data(name, session)
    print(f"Hashed name: {hashed_name}")  # ADDED
    is_session_valid = decoder.verify_session(hashed_name, session, user.status)  # ADDED
    print(f"Session valid: {is_session_valid}")  # ADDED
    if is_session_valid:
        decoded_session = decoder.decode_session(session)
        manager.append_room(name, Room(name))
        connection = Connection(user.name, session, websocket)
        try:
            manager.append_room_connection(name, connection)
            room = await manager.connect_room(name, connection)
            room_hadnler = WsHandler(room, connection)
            try:
                while True:
                    data = await websocket.receive_json()
                    hadnleFunc = room_hadnler.hadnlers(data["status"])
                    await hadnleFunc(
                        {
                            "username": data["username"],
                            "message": data["message"],
                            "admin": decoded_session["admin"],
                            "room": room_obj,
                            "user": user,
                        }
                    )
            except WebSocketDisconnect as e:
                await room.disconnect(connection)
                manager.close_room(name)
                await room.broadcast(202, f"{user.name} left chat", user.name)
                print(f"websocket connection closed: {e}")
        except RuntimeError as e:
            manager.delete_connections(name)
            print(f"runtime error: {e}")
    else:  # ADDED
        print("Session verification failed!")  # ADDED
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)  # ADDED
