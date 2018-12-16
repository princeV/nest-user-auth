# Simple nestjs cli setup with auth

## Initialize project:
- Make sure to have the latest version of node.
- Install the next cli (command line interface)
```bash
$ npm i -g @nestjs/cli
```
- Creat a new angular project.
```bash
$ nest new nest-user-auth
```

### Folder structure:
```bash
project  
│   node_modules
└───src
│   app.controller.spec.ts
│   app.controller.ts
...
```

## User Module
Let's first generate the user __module__ via cli that we want to use:   
```bash
$ nest g mo user
```

### Data Transfer Object (dto)
Create folder "dto" under user.
Add file "create-user.dto.ts" to the file with the following content:
```typescript
...
export class CreateUserDto {
  readonly username: string;
  readonly password: string;
  readonly email: string;
  readonly roles: Array<string>;
}
```
* This will be the structure of the input object to create a user.  

### Interface
Create folder "interface" under user.
We will use class instead of interface even if the name is suggesting the use of an interface.  
Add file "user.interface.ts" to the file with the following content:
```typescript
...
export class User {
  constructor(
    public username: string,
    public password: string,
    public email: string,
    public roles: Array<string>
  ){}
}
```
* This will be the structure of the returned object from the database.  


### Mongoose
We also want to directly add the mongoose part to have it later available in our service.
```bash
$ npm install --save @nestjs/mongoose mongoose
```

#### user schema
create Schema
Create folder "schemas" under user.
Add the file "user.schema.ts" with the following code:
```typescript
import * as mongoose from 'mongoose';

export const UserSchema = new mongoose.Schema({
  username: {
    type : String,
    required : true,
    unique : true
  },
  password: {
    type : String,
    required : true
  },
  email: {
    type : String,
    required : true,
    unique : true
  },
  roles: [String]
});
```

#### Add bcrypt
Install bcrypt - this will be used for hashes and salting:
```bash
$ npm i -s bcrypt
```
File "user.schema.ts":
```typescript
import * as bcrypt from 'bcrypt';
...
UserSchema.pre('save', async function(next){
  const user = this;
  const hash = await bcrypt.hash(this.password, 10);
  this.password = hash;
  next();
});
UserSchema.methods.isValidPassword = async function(password){
  const user = this;
  const compare = await bcrypt.compare(password, user.password);
  return compare;
}
...
```
Now the password gets automatically hashed and the user schema offers a method to check weather a password is valid or not.


#### Import in app module
add the following code to the app.module file:
```typescript
...
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [MongooseModule.forRoot('mongodb://localhost/nest'), ...],
  ...
})
```
#### Import in user module
add the following code to the user.module file:
```typescript
...
  imports: [MongooseModule.forFeature([{ name: 'User', schema: UserSchema }])],
...
```

### Service

Next is the __service__, make sure to specify the directory, else it will be generated in the src folder and added to the app.module:
```bash
$ nest g s user/user
```

Create the following code in file:

```typescript
import { Model } from 'mongoose';
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './interfaces/user.interface';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
  //to be changed with env variables
  private readonly saltRounds = 10;

  constructor(@InjectModel('User') private readonly userModel: Model<User>) {}

    async create(createUserDto: CreateUserDto): Promise<User> {
      createUserDto.password = await this.getHash(createUserDto.password);
      const createdUser = new this.userModel(createUserDto);
      return await createdUser.save();
    }

    async findAll(): Promise<User[]> {
      return await this.userModel.find().exec();
    }

    async findByUsername(username: string): Promise<User[]> {
      return await this.userModel.findOne({ username: username }).exec();
    }

}
```
* use Model from mongoose for mongodb query usage (will be added later)
* use User (create output) as interface and CreateUserDto (create input) as the creation structure

### Controller
Add a user controller via:
```bash
$ nest g co user
```
If we stick to that order, the user component will be automatically added to its module.

In the controller add the following code:

```typescript
import { Controller, Get, Post, Body, Put, Param, Delete, Query } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UserService } from './user.service';
import { User } from './interfaces/user.interface';


@Controller('api/user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    this.userService.create(createUserDto);
  }

  @Get()
  async findAll(): Promise<User[]> {
    return this.userService.findAll();
  }

  @Get(':username')
  findOne(@Param('username') username) {
    return this.userService.findByUsername(username);
  }

}
```
This sets the routes (api/user) and adds the following methods:
* Post will create a user via service
* Get will get a list of all users
* Get with path :username -> api/user/username will get a single user with the given findByUsername

## Authentication
Install the following modules for authentication with JWT:
```bash
$ npm install --save @nestjs/passport passport passport-jwt jsonwebtoken
```
With the authentication we would like to take care of the following:
* login
* logon
* register
* passport usage
* jwt Strategy

Dependency to user -> we need to be able to use the UserService.

### Module
Add a module via
```bash
$ nest g mo auth
```

### Services
Add a service via:
auth service
```bash
$ nest g s auth/auth
```
```typescript
import * as jwt from 'jsonwebtoken';
import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(private readonly usersService: UsersService) {}

  async createToken() {
    const user: JwtPayload = { email: 'user@email.com' };
    return jwt.sign(user, 'secretKey', { expiresIn: 3600 });
  }

  async validateUser(payload: JwtPayload): Promise<any> {
    return await this.usersService.findOneByEmail(payload.email);
  }
}
```
### Jwt Strategy
Create a file "jwt.strategy.ts" in the auth folder.

### Auth controller
```bash
$ nest g co auth
```
