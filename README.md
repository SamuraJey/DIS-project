# FastAPI + React

<div>
<img src="assets/fastapi-logo.png" alt="fastapi-logo" height="60" />
 <img src="assets/sql-alchemy.png" alt="sql-alchemy" height="60" />
<img src="assets/react-logo.png" alt="react-logo" height="60" />
<img src="assets/typescript.png" alt="typescript-logo" height="60" /> 
</div>

A small Web Messenger with **[End-to-End](https://en.wikipedia.org/wiki/End-to-end_encryption)**  encryption 

---
## Features

- **[FastAPI](https://fastapi.tiangolo.com/)** (Python 3.9)
  - JWT authentication
- **[React](https://reactjs.org/)** (with Typescript)
  - [react-router v6](https://reactrouter.com/docs/en/v6/getting-started/overview/) to handle routing
  - [react-hooks](https://reactjs.org/docs/hooks-intro.html)
  - [axios](https://github.com/axios/axios) to send requests
- **[SqlAlchemy](https://www.sqlalchemy.org/)** for ORM
- **[Pytest](https://docs.pytest.org/en/latest/)** for backend tests
- **[Prettier](https://prettier.io/)**/**[ESLint](https://eslint.org/)** (Typescript)
- **Ruff** todo link and configs

## Docker
WARNING NOT WORKING FOR NOW
```bash
docker compose up
```
Go to http://localhost:8000/


## Quick Dev Start
- Run Backend
  - Create virtual environment <br>
      ```bash 
      python -m venv .venv
      ```
   - Activate virtual environment
       ```bash 
       Windows: env/Scripts/activate
       Linux: source env/bin/activate
       ```
    - Install requirements
       ```bash 
       pip install -r backend/requirements.txt
       ```
    - Init database
      ```bash
      python backend/app/db/init_tables.py
      ```
    - Run FastAPI server
       ```bash
       cd backend
       cd app
       uvicorn main:app --host '<ip>' --port <port>
       ```
- Run Frontend
  - Install all node packages (and pray that it will work)
    ```bash 
    cd frontend
    npm install
    ```
  - Run react server
    ```bash
    npm start
    ```

## Examples

<details>
<summary>Click to expand examples</summary>

### Home page
![Home page](assets/home.gif)

### Creating a room
![Creating a room](assets/create_room.gif)

### Message
![Message](assets/test_message.gif) 

### Adding other users
To add a new user, it is enough to share a link
![Adding other users](assets/new_user.gif) 

### Sharing the encryption key
The user needs an encryption key to decrypt other people's messages and send their own
![Sharing the encryption key](assets/key_sharing.gif)

### User status
Users have online and offline statuses
![User status](assets/online_status.gif)

### Ban users
Admin can ban users
![Ban users](assets/user_ban.gif)

### Deleting a room
When deleting a room, users and their messages are also deleted
![Deleting a room](assets/delete_room.gif)

</details>




