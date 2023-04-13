# Express with Passport.js
Network Security Authoritzation and Authentication (NSAA) Laboratory.
The objective is to practice different types of authentication and authoritzation.

# Instructions
```
cd express-app
npm install
node index.js
```

You should fill the "config.json" file located inside "express-app" folder with needed parameters.

Then the server will be listening on localhost port 3000: http://localhost:3000

Localhost is considered a realiable channel. Then, no tls is needed for testing.

# Tips
## Database file exclusion
If you do not want to upload the database file ("database.json") you can use git file exclusion:
```
git update-index --assume-unchanged express-app/database.json
```
If you want to undo the file exclusion:
```
git update-index --no-assume-unchanged express-app/database.json
```

# Scrypt parameters

## N
𝑁 is the one and only work factor.
Memory and CPU usage scale linearly with 𝑁.
The reason 𝑁 must be a power of two is that to randomly select one of the 𝑁 memory slots at each iteration, scrypt converts the hash output to an integer and reduces it mod 𝑁. If 𝑁 is a power of two, that operation can be optimized into simple (and fast) binary masking.

## r
It makes the core hash function in scrypt 2𝑟 wider.
It does that by iterating the hash function 2𝑟 times, so both memory usage (to store the hash values) and CPU time scale linearly with it. That is, if 𝑟 doubles the resources double.

## p
It is a parallelization parameter. 𝑝 instances of the mixing function are run independently and their outputs concatenated as salt for the final PBKDF2.
𝑝 > 1 can be handled in two ways:
- Sequentially, which does not increase memory usage but requires 𝑝 times the CPU and wall clock time
- Parallelly, which requires 𝑝 times the memory and effective CPU time, but does not increase wall clock time.

# Sources
- https://github.com/juanelas/scrypt-mcf
- https://words.filippo.io/the-scrypt-parameters/