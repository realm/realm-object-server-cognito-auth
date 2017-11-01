# realm-object-server-cognito-auth
Cognito authentication provider for Realm Object Server


## Quick Start (TypeScript)

Start by creating a new project (if you haven't already done so):


    npm install -g realm-object-server
    ros init cognito-demo -t ts
    cd cognito-demo

Then install the custom auth provider from NPM:

    npm install --save realm-object-server-cognito-auth

Next, edit `src/index.ts`, making sure you've adjusted the auth provider configuration:

```typescript
import { BasicServer } from "realm-object-server";
import * as path from "path";

import { CognitoAuthProvider } from "realm-object-server-cognito-auth";

const server = new BasicServer();
const cognitoAuthProvider = new CognitoAuthProvider({
    region: "us-east-1",
    userPoolId: "us-east-1_XXXXXXXXX",
});

server.start({
    dataPath: path.join(__dirname, "..", "data"),
    authProviders: [ cognitoAuthProvider ],
});
```

And then start!

    npm start


## Quick Start (JS)

Start by creating a new project (if you haven't already done so):


    npm install -g realm-object-server
    ros init cognito-demo -t js
    cd cognito-demo

Then install the custom auth provider from NPM:

    npm install --save realm-object-server-cognito-auth

Next, edit `src/index.js`, making sure you've adjusted the auth provider configuration:

```javascript
const BasicServer = require("realm-object-server").BasicServer;
const path = require("path");
const CognitoAuthProvider = require("realm-object-server-cognito-auth").CognitoAuthProvider;

const server = new BasicServer();
const cognitoAuthProvider = new CognitoAuthProvider({
    region: "us-east-1",
    userPoolId: "us-east-1_XXXXXXXXX",
});

server.start({
    dataPath: path.join(__dirname, '../data'),
    authProviders: [ cognitoAuthProvider ],
});
```

And then start!

    npm start


# CHANGELOG

## Release 1.0.0

* Initial Release
