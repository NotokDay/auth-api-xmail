# NodeJS Auth REST API example with Express, Mysql, and JWT
This is an improvement to [Desirekaleba's project](https://github.com/desirekaleba/node-mysql-jwt-auth) for our [XMail project](https://github.com/NotokDay/XMail-SpamChecker).
## Features
1. User can sign up
2. User can sign in

## API endpoints

1. `POST /api/auth/signup`: Creates a new user
2. `POST /api/auth/signin`: Logs in a user
3. `GET /api/auth/verify/:token`: Verifies user's email address
4. `POST /api/auth/changepassword`: Changes user's password using their OLD password
5. `GET /api/auth/reset/:encodedEmail`: Sends a one-time-password to user's email
6. `POST /api/auth/resetpassword`: Will reset user's password

## Tools
* NodeJS/Express: Server
* MySQL: Storage
* JWT: Token based authentication
* bcryptjs: Password security
* winston/morgan: Logs
* Joi: Validations

## Available scripts
* `start`: Starts the server with node
* `start:dev`: Starts the server in watch mode
* `db:up`: Creates the database
* `db:down`: Drops the database
* `tables:up`: Creates database tables
* `db:init`: Creates both the database and tables

## Getting started

You can either fork this repository or clone it by starting your terminal, then change the directory to where you would like to save it and run

```sh
git clone https://github.com/NotokDay/auth-api-xmail.git
```
Change to the newly downloaded directory with

```sh
cd node-mysql-jwt-auth
```

Rename the file named `.env.example` to `.env` and update the variable values with valid ones

Install the required dependencies with

```sh
npm install
```

Initialize the database with

```sh
npm run db:init
```

Start the app with

```sh
npm start
```

You can also start it in watch mode with

```sh
npm run start:dev
```
