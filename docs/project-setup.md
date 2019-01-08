# Simple nestjs cli setup with auth

## Initialize project:
- Make sure to have the latest version of node.
- Install the next cli (command line interface)
```bash
$ npm i -g @nestjs/cli
```
- Creat a new angular project.
```bash
$ nest new <project name>
```
Enter and confirm based on your project.

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

### Data Transfer Objects (dto)
As a next step we will create our Data Transfer Object that will be used to transfer the data of the user via our api.
For that we create a __subfolder in user__ with the name __dto__.

We first define the logon user object that we use to log on with a user:  
Create the file __logon-user.dto.ts__:
```typescript
export class LogonUserDto {
  readonly email: string;
  readonly password: string;
}
```
For the logon we are only interested in email and password as this is how we can uniquely identify a user.

The second dto we need is the one we use to create a user via http post later.  
Add file __create-user.dto.ts__ with the following content in the dto folder:
```typescript
export class CreateUserDto {
  readonly username: string;
  readonly password: string;
  readonly email: string;
  readonly roles: Array<string>;
}
```
This object has all data that is relevant from a create-user form perspective.  

__Note__:  We have username here but this will not be user for logon, we use email to identify the user during logon.

### Interface
Create folder "interface" under user.
We will use class instead of interface even if the name is suggesting the use of an interface.  
Add file __user.interface.ts__ to the file with the following content:
```typescript
export class User {
  constructor(
    public username: string,
    public password: string,
    public email: string,
    public roles: Array<string>
  ){}
}
```
* This will be the structure of the returned object from the database


### Mongoose
We also want to directly add the mongoose part to have it later available in our service.
```bash
$ npm install --save @nestjs/mongoose mongoose
```

#### Import into app module
Let's import the mongoose module into our application.
For that we need to change the code of the **_app.module.ts_** file:
```typescript
...
import { MongooseModule } from '@nestjs/mongoose';
...
@Module({
  imports: [
    MongooseModule.forRoot('mongodb://localhost:27017/nest'),
    UserModule
  ],
  ...
})
```
We now imported the module and added it to the app module imports with forRoot - directly providing the db-server and db-name.  
__Note__:  
This should be stored in a seperate env-setup file or any other simillar way for production.

#### Create the user schema
create Schema
Create folder "schema" under user.
Add the file __user.schema.ts__ with the following code:
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

##### Add bcrypt
Now we also want to add bcrypt as our main salt and hash library.
We directly add it into the mongoose schema - this could be handled differently but as of this it's an easy solution.
Install bcrypt:
```bash
$ npm i -s bcrypt
```
Update file **_user.schema.ts_** add those two methods:
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

#### Import into user module
Next we want to add the mongoose module and the user schema to our user module to be able to use it there.

Change the **_user.module.ts_** and add the imports as follows:

```typescript
import { MongooseModule } from '@nestjs/mongoose';
import { UserSchema } from './schema/user.schema';
...
@Module({
  imports: [
    MongooseModule.forFeature([{ name: 'User', schema: UserSchema }])
  ]
})
...
```
## Authentication (JWT and passport)
Install the following modules for authentication with JWT (Json web token) and passport:
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
Then we insert the following code:
```typescript
import * as jwt from 'jsonwebtoken';
import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  constructor() {}

  async createToken(payload: any): Promise<any> {

    const expiresIn = 3600 ;
    const secretOrKey = 'secretKey';
    const user = {
      "id":payload.id,
      "username": payload.username,
      "roles": payload.roles
    };

    return jwt.sign(user, secretOrKey, {expiresIn});
  }

  async decodeToken(token: any): Promise<any> {
    return jwt.decode(token);
  }
}
```
We now have two methods from the service:
* One to create a JWT token (note: secretKey should be stored in an env file/variable for production)
* And the second one to decode a token (note: this is only required for us to check the roles for the user later on)

### Jwt Strategy
Create a file __jwt.strategy.ts__ in the auth folder.
```typescript
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'secretKey',
    });
  }

/*  Seems like the check for the jwt token is done in the background
    This function has to be implemented but will only be used for
    additional checks on the payload
*/
  async validate(payload: any, done: Function) {
    done(null, payload);
    //to do -> maybe check if user exsists -> used to make sure deleted users
    // do not have any possibility to do things anymore while jwt is still valid
  }
}
```
### Roles and UseGuards
Now we also want to enable different roles for the users and grant/deny access based on roles.

For that we want to create our own decorator for quicker implementation later.

Create a new file in the auth folder called __roles.decorator.ts__:
```typescript
import { ReflectMetadata } from '@nestjs/common';

export const Roles = (...roles: string[]) => ReflectMetadata('roles', roles);
```

Next we will create the guard for the roles that we can later reuse in the user controller. Create another file called __roles.guard__ in the auth folder:

```typescript
import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { AuthService } from './auth.service';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector, readonly authService: AuthService) { }

  async canActivate(context: ExecutionContext): boolean {
    const roles = this.reflector.get<string[]>('roles', context.getHandler());
    if (!roles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    //check if auth token is available
    if(!request.headers.authorization){
      throw new UnauthorizedException();
      return false;
    }
    const token = request.headers.authorization.replace('Bearer ','');
    const payload = await this.authService.decodeToken(token);

    const hasRole = () => payload.roles.some((role) => roles.includes(role));

    const validRequest = payload && payload.roles && hasRole();
    if (!validRequest) {
      throw new UnauthorizedException();
    }
    return validRequest;
  }
}
```
This class implements the canActivate method. In it we decode the JWT token and check the payload for the given roles.

If the required role exsists it will pass, else it will fail.


### auth module update
We also need to add additional dependencies to our auth module
```typescript
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { AuthController } from './auth.controller';

@Module({
  providers: [AuthService, JwtStrategy],
  exports: [AuthService]
})
export class AuthModule {}
```

### Adding authorization to the app

#### Import into app module
Now we will add the authentication module into our main app.
Add the following code to the **_app.module_** file:
```typescript
...
import { AuthModule } from './auth/auth.module';
...
@Module({
  imports: [
      ...,
      AuthModule
    ],
  ...
})
```
the AuthModule will be created later...

#### Import into user module
And we will also add it to the user module.
Add the following code to the **_user.module_** file:
```typescript
...
import { AuthModule } from '../auth/auth.module';
...
@Module({
  imports: [
    ...,
    AuthModule)
  ]
  ...
})
export class UserModule {}
```

#### User Exception
Let's also create a custom exception for an invalid user logon.
For that we create a new folder: __exception__.
In the folder we create a file called __user-credential.exception.ts__:

Add this code:
```typescript
import { HttpException, HttpStatus } from '@nestjs/common';

export class UserCredentialException extends HttpException {
  constructor() {
    super('Username or password is not correct', HttpStatus.BAD_REQUEST);
  }
}
```
This will extend the HttpExceptin with the given message and set the http return status to BAD_REQUEST.


### User Service

Next is the __service__, make sure to specify the directory, else it will be generated in the src folder and added to the app.module:
```bash
$ nest g s user/user
```

Create the following code in the file:

```typescript
import { Model } from 'mongoose';
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './interface/user.interface';
import { CreateUserDto } from './dto/create-user.dto';
import { AuthService } from '../auth/auth.service';
import { UserCredentialException } from "./exception/user-credential.exception.ts";


@Injectable()
export class UserService {

  constructor(@InjectModel('User')
                private readonly userModel: Model<User>,
                private readonly authService: AuthService
              ) {}

    async create(createUserDto: CreateUserDto): Promise<User> {
      const createUser = new this.userModel(createUserDto);
      return await createUser.save();
    }

    async logon(logonUserDto: any): Promise<any> {
      const user = await this.userModel.findOne({username: logonUserDto.username}).exec();

      if(user && await user.isValidPassword(logonUserDto.password)){
        return this.authService.createToken(user);
      }
      throw new UserCredentialException()
    }

    async findAll(): Promise<User[]> {
      return await this.userModel.find().exec();
    }

    async findByUsername(username: string): Promise<User[]> {
      return await this.userModel.findOne({ username: username }).exec();
    }
}
```
* use Model from mongoose for mongodb query usage
* use User (create output) as interface and CreateUserDto (create input) as the creation structure

### Controller
Add a user controller via:
```bash
$ nest g co user
```
If we stick to that order, the user component will be automatically added to its module.

In the controller add the following code:

```typescript
import { Controller, UseGuards, Get, Post, Body, Put, Param, Delete, Query, Req } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { LogonUserDto } from './dto/logon-user.dto';
import { UserService } from './user.service';
import { User } from './interfaces/user.interface';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from '../auth/roles.decorator';
import { RolesGuard } from '../auth/roles.guard';

@Controller('api/user')
@UseGuards(RolesGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}
  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    this.userService.create(createUserDto);
  }
  @Post('logon')
  async userLogon(@Body() logonUserDto: LogonUserDto): Promise<any> {
    return await this.userService.logon(logonUserDto);
  }
  @Get()
  @UseGuards(AuthGuard('jwt'))
  @Roles('admin')
  async findAll(@Req() request): Promise<User[]> {
    // all userdata here (no pwd)
    console.log(request.user);
    return this.userService.findAll();
  }
  @Get(':username')
  findOne(@Param('username') username) {
    return this.userService.findByUsername(username);
  }
  @Put(':id')
  update(@Param('id') id, @Body() updateCatDto) {
    return `This action updates a #${id} user`;
  }
  @Delete(':id')
  remove(@Param('id') id) {
    return `This action removes a #${id} user`;
  }
}

```
This sets the routes (api/user) and adds the following methods:
* Post will create a user via service
* Get will get a list of all users -> protected by useGuards that will be implemented later
* Get with path :username -> api/user/username will get a single user with the given findByUsername
