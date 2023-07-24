# Containerized Task Management Application

## Installation

- Clone this repo
- Install a stable version of docker and docker compose on your target machine [Official Docker Documentation](https://docs.docker.com/engine/install/)
- To start the application, run
```shell
docker compose build
docker compose up -d
```
- To check the status of any of the services, run `docker compose ps`

## About the Application

This application consists of three services: 
1. GoLang Backend Application
2. MySQL Database
3. nginx Reverse Proxy

These three services are orchestrated using docker compose

Due to time constraints of the task, certain simplifying assumptions have been made to the scope of the problem. 

Each of the assumptions will be discussed in more detail later.

### API Endpoints

#### Initial Setup

The first step is to create a user and login. This will generate an auth token which will be stored in your cookies for further authentication and authorization.

User must be logged in to create any tasks, roles or groups. 

Assumption 1: There is no admin user which means any user, irrespective of role or group, can create or delete new roles and groups as well as create new tasks. Another consequence of this assumption is that a user must delete their own account.


`POST /signup`

The endpoint for signup requires 'Email' and 'Password' in JSON format passed in the body of the HTTP Request.

`POST /login`

The login endpoint similarly requires the same. This endpoint creates the auth token and adds to your cookies.

`GET /logout`

The logout endpoint deletes the cookie generated for the user.

`POST /addtask`

Adding a new task requires 'Description' which must be unique and 'Completed', a boolean value

`POST /addrole`

To add a new role, it only requires 'RoleName' which must be unique

`POST /addgroup`

To add a new group, it requires 'GroupName' which must also be unique

`DELETE /deleterole`

To delete an existing role, it requires 'RoleName'

`DELETE /deletegroup`

To delete an existing group, it requires 'GroupName'

`POST /user/addrole`

This assigns a role to a user, it needs 'RoleName'

Assumption 2: Assumes a user can only have one role.

`POST /user/addgroup`

This endpoint assigns a user to a group, and only needs 'GroupName'

`DELETE /user/deleterole`

This deletes a role from a user, and does not require any params

`DELETE /user/deletegroup`

This deletes a user from a group, and takes in only the 'GroupName'

`POST /task/addrole`

This adds an accessibility role to a task and takes in 'TaskDescription' and 'RoleName'

`POST /task/addgroup`

This endpoint adds an accessibility group to a task and takes in 'TaskDescription' and 'GroupName'

`DELETE /task/deleterole`

This removes a role from being able to access a task and takes in 'TaskDescription' and 'RoleName'

`DELETE /task/deletegroup`

This removes a group from being able to access a task and takes in 'TaskDescription' and 'GroupName'

`PATCH /updatetask`

This endpoint implements Identity and Access Management and allows users which are part of authorized roles AND groups to modify the task, while taking in 'oldDescription', 'newDescription', and 'Completed'

`DELETE /deletetask`

This endpoint also implements IAM and allows authorized users to delete a task by providing 'Description'

`DELETE /deleteuser`

This can only be done by the user themself and takes no params

`POST /uploadusers`

This endpoint takes in a CSV in the HTTP request body under form-data

Assumption 3: This CSV can only take in one role and group at a time for a single user

`POST /uploadtasks`

This endpoint also takes in a CSV in the HTTP request body under form-data

This uses the same assumption as above but for tasks

### Data Retention

All Deletions are Soft Deletions with Deleted_at being stored in the tables.

MySQL scheduled procedures can be used to clean up these rows at fixed time intervals
