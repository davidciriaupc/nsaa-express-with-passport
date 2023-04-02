const fs = require('fs');
const scryptMcf = require('scrypt-mcf')

class FileDatabase {
    constructor(path) {
        this.path = path;
    }

    async registerUser(name, password) {
        const database = this.readJsonFile()
        const user = database['users'][name]

        if (user) {
            console.log('User already registered, you should choose another name')
            return null
        }

        database['users'][name] = { 
            'password': await scryptMcf.hash(password, { derivedKeyLength: 32, scryptParams: { logN: 17, r: 8, p: 1 } }) // fast setup (<1s).
            // 'password': await scryptMcf.hash(password, { derivedKeyLength: 32, scryptParams: { logN: 19, r: 15, p: 1 } }) // slow setup (>3s).
        }

        this.writeJsonFile(database)

        return database
    }

    getUser(name) {
        const database = this.readJsonFile()
        const user = database['users'][name]

        if (user) {
            console.log(`User found with name ${name}`)
        } else {
            console.log(`User not found with name ${name}`)
        }

        return user;
    }

    readJsonFile() {
        try {
            const data = fs.readFileSync(this.path, 'utf8')
            const json_data = JSON.parse(data)
            return json_data
        } catch (err) {
            throw err
        }
    }

    writeJsonFile(content) {
        try {
            fs.writeFileSync(this.path, JSON.stringify(content))
            // file written successfully
        } catch (err) {
            throw err
        }
    }
}

module.exports = FileDatabase;