import users from '../data/user.js';

class User {

    createUser(user) {
        console.log(`---> userModel::createUser ${user.username}`);

        users.push(user);
        return users.find(element => element.username == user.username);


    }

    loginUser(user) {

        console.log(`---> userModel::loginUser ${user.username}`);

        return users.find(element => (element.username == user.username))
    }
    grantUser(user) {
        console.log(`---> userModel::grantUser ${user.username}`);
        users.forEach(element => {
            if (element.username == user.username) {
                element.grants = user.grants
            };
        });
        return users.find(element => (element.username == user.username))
    }
    delGrantUser(user) {
        console.log(`---> userModel::delGrantUser ${user.username}`);
        users.forEach(element => {
            if (element.username == user.username) {
                user.grants.forEach(ele => {
                    const index = element.grants.indexOf(ele);
                    if (index > -1) {
                        element.grants.splice(index, 1)
                    }
                });
            };
        });
        return users.find(element => (element.username == user.username))
    }

    addGrantUser(user) {
        console.log(`---> userModel::addGrantUser ${user.username}`);
        users.forEach(element => {
            if (element.username == user.username) {
                element.grants = element.grants.concat(user.grants)
            };
        });
        return users.find(element => (element.username == user.username))
    }
    newPass(user) {
        console.log(`---> userModel::newPass ${user.username}`);
        users.forEach(element => {
            if (element.username == user.username) {
                element.password = user.newpassword
            };
        });
        return users.find(element => (element.username == user.username))
    }
    oldHash(user) {
        const usr = users.find(element => (element.username == user.username))
        return usr.password
    }
    deactivate(user) {
        console.log(`---> userModel::deactivate ${user.username}`);
        users.forEach(element => {
            if (element.username == user.username) {
                element.active = 0
            };
        });
        return users.find(element => (element.username == user.username))
    }
    checkActive(user) {
        console.log(`---> userModel::checkActive ${user.username}`);
        const usr = users.find(element => (element.username == user.username))
        console.log(user)
        console.log(usr)
        return usr.active
    }
    reactivate(user) {
        console.log(`---> userModel::reactivate ${user.username}`);
        users.forEach(element => {
            if (element.username == user.username) {
                element.active = 1
            };
        });
        return users.find(element => (element.username == user.username))
    }
}

export default new User();