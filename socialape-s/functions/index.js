const functions = require('firebase-functions');
const admin = require('firebase-admin');
const app = require('express')();
const firebase = require('firebase');
const firebaseConfig = {
    apiKey: "AIzaSyCNglAaGTiOiAOCikEttseo4uRaKnBw1Ns",
    authDomain: "socialape-stu.firebaseapp.com",
    databaseURL: "https://socialape-stu.firebaseio.com",
    projectId: "socialape-stu",
    storageBucket: "socialape-stu.appspot.com",
    messagingSenderId: "559553866876",
    appId: "1:559553866876:web:a4d125936e4f6cbb39adf9",
    measurementId: "G-LW8Y088D3Y"
};
// initial
admin.initializeApp();
firebase.initializeApp(firebaseConfig);

// get all scream
app.get('/screams', (request, response) => {
    admin
        .firestore()
        .collection('screams')
        .orderBy('createAt','desc')
        .get()
        .then((data) => {
            let screams = [];
            data.forEach((doc) => {
                screams.push({
                    screamId : doc.id,
                    body : doc.data().body,
                    userHandle : doc.data().userHandle,
                    createAt : doc.data().createAt
                });
            })
            return response.json(screams);
        })
        .catch((error) => {
            return console.error(error);
        });
});

//firebase authorized function
const fbAuth = (request, response, next) => {
    let idToken;
    if( request.headers.authorization && request.headers.authorization.startsWith('Bearer ') ){
        idToken = request.headers.authorization.split('Bearer ')[1];
    } else {
        console.error('No token found');
        return response.status(403).json({error : 'Unanthorized'});
    }

    return admin.auth().verifyIdToken(idToken)
        .then( decodedToken => {
            request.user = decodedToken;
            return admin.firestore().collection('users')
                        .where('userId', '==', request.user.uid)
                        .limit(1)
                        .get();
        })
        .then( (data) => {
            request.user.userHandle = data.docs[0].data().userHandle;
            return next();
        })
        .catch(error => {
            console.error('Error while verifying token', error);
            return response.status(403).json(error);
        })
}
 
// create new scream
app.post('/scream', fbAuth, (request, response) => {
    const newScream = {
        body : request.body.body,
        userHandle : request.user.userHandle,
        createAt : new Date().toISOString()
    }
    admin
        .firestore()
        .collection('screams')
        .add(newScream)
        .then( (doc) => {
            return response.json({ message : `document ${doc.id} create successfully` });
        })
        .catch((error) => {
            console.error(error);
            return response.status(500).json({error : 'Something went wrong'});
        })
})

// validate funtion
const isEmpty = (string) => {
    if(string.trim() === '')
        return true;
    else
        return false;
}

// Route
let tokenId, userId;
app.post('/signup', (request, response) => {
    const newUser = {
        email : request.body.email,
        password : request.body.password,
        confirmPassword : request.body.confirmPassword,
        userHandle : request.body.userHandle
    }
    // Validate
    let errors = {};
    if( isEmpty(newUser.email) )
        errors.email = 'Must not be empty';
    if(newUser.password !== newUser.confirmPassword)
        errors.confirmPassword = 'Password must match';
    if( isEmpty(newUser.userHandle) )
        errors.userHandle = 'Must not be empty';
    if(Object.keys(errors).length > 0)
        return response.status(400).json({errors});

    return admin.firestore().doc(`/users/${newUser.userHandle}`)
        .get()
        .then( (doc) => {
             if( doc.exists ){
                return response.status(400).json({ userHandle : 'This user handle already taken' });
             } else {
                return firebase.auth().createUserWithEmailAndPassword(newUser.email, newUser.password);
             }
        })
        .then( data => {
            userId = data.user.uid;
            return data.user.getIdToken();
        })
        .then((token) =>{
            tokenId = token;
            const userCredential = {
                userHandle : newUser.userHandle,
                email : newUser.email,
                createAt : new Date().toISOString(),
                userId
            }
            return admin.firestore().doc(`/users/${newUser.userHandle}`)
                .set(userCredential);
        })
        .then( () => {
            return response.status(201).json({ tokenId });
        })
        .catch( (error) => {
            console.error(error);
            if( error === 'auth/email-already-in-use' )
                return response.status(400).json({email : 'Email already in use'});
            else
                return response.status(500).json({ error : error.code });
        })
})

app.post('/login', (request, response) => {
    const user = {
        email : request.body.email,
        password : request.body.password
    }
    //validate
    let errors = {};
    if(isEmpty(user.email))
        errors.email = 'Email must not be empty';
    if(isEmpty(user.password))
        errors.password = 'Password must not be empty';
    if(Object.keys(errors).length > 0)
        return response.status(400).json({errors});

    //login
    return firebase
        .auth()
        .signInWithEmailAndPassword(user.email, user.password)
        .then((data) => {
            return data.user.getIdToken();
        })
        .then((token) => {
        return response.json({ token });
        })
        .catch( (error) => {
            console.error(error);
            if( error.code === 'auth/wrong-password' ){
                return response.status(403).json({ general : 'Wrong credentials, please try again' })
            } else {
                return response.status(500).json({error : error.code});
            }
        })
})

exports.api = functions.https.onRequest(app);