# API Documentation

## Overview

This document provides details on the authentication API, including available endpoints, HTTP methods, request parameters, response formats, and validation rules.

---

## 1. Register User

**Endpoint:** `/auth/register`\
**Method:** `POST`

### Description

Registers a new user. The provided username, password, and email are validated using regex. Upon successful registration, an activation email is sent to the user.

### Request Body

```json
{
  "username": "username",
  "password": "password",
  "email": "example@domain.com"
}
```

### Validations

- **Username:**

  - Regex: `^(?=.{8,20}$)[-A-Za-z0-9!"#$%&'()*+,.\/;<=>?@\[\]\\^_{|}~]+$`
  - Must be 8 to 20 characters long.

- **Email:**

  - Regex: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

- **Password:**

  - Regex: `^(?=.{8,20}$)[-A-Za-z0-9!"#$%&'()*+,.\/;<=>?@\[\]\\^_{|}~]+$`
  - Must be 8 to 20 characters long.

### Response

```
Registration pending for user: username
```

### Notes

After registration, an activation email containing a link to activate the account is sent to the user.

---

## 2. Activate User

**Endpoint:** `/auth/activate`\
**Method:** `GET`

### Description

Activates the user's account using the token provided in the activation email.

### Query Parameters

- `token`: The activation token.
- `username`: The username of the account to activate.

### Example URL

```
/auth/activate?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...&username=username
```

### Response

```
User: username activated successfully
```

### Notes

Upon activation, the user's record in the database is updated, setting `is_active` to `true`.

---

## 3. User Login

**Endpoint:** `/auth/login`\
**Method:** `POST`

### Description

Authenticates the user and returns a JWT token.

### Request Body

```json
{
  "username": "username",
  "password": "password"
}
```

### Response

```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## 4. Get User Information

**Endpoint:** `/auth/user`\
**Method:** `GET`

### Description

Retrieves details about the authenticated user. The request must include the Bearer token in the header.

### Headers

```
Authorization: Bearer <token>
```

### Response

```json
{
  "username": "username",
  "email": "example@domain.com",
  "created_at": "2025-02-04T17:15:15.399482",
  "updated_at": "2025-02-04T17:15:15.399482",
  "last_login": "2025-02-04T17:17:55.543514",
  "is_active": true
}
```

---

## 5. Update User Password

**Endpoint:** `/auth/user`\
**Method:** `PUT`

### Description

Updates the authenticated user's password. The user must provide both the current and new passwords.

### Headers

```
Authorization: Bearer <token>
```

### Request Body

```json
{
  "old_password": "password",
  "new_password": "password1"
}
```

### Response

```
Password for user username reset successfully
```

---

## 6. Delete User Account

**Endpoint:** `/auth/user`\
**Method:** `DELETE`

### Description

Deletes the authenticated user's account.

### Headers

```
Authorization: Bearer <token>
```

### Response

```
User username deleted successfully
```
