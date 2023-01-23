const sqliteConnection = require("../database/sqlite");
const AppError = require("../utils/AppError")

const { hash, compare } = require ("bcryptjs")

class UsersController {
    async create(request, response) {
        const { name, email, password } = request.body;

        const hashedPassword = await hash(password, 8);
        
        const database = await sqliteConnection();
        const checkUserExists = await database.get("SELECT * FROM users WHERE email = (?)", [email])

        if(!name) {
            throw new AppError("O nome e obrigatorio")
        };

        if(checkUserExists) {
            throw new AppError("Este email ja esta em uso.")
        }

        await database.run(
            'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
             [name, email, hashedPassword]
        );

        return response.status(201).json()
}

    async update(request, response) {
        const { name, email, password, old_password } = request.body;
        const { id } = request.params;

        const database = await sqliteConnection();
        const user = await database.get("SELECT * FROM users WHERE id = (?)", [id]);

        if (!user) {
            throw new AppError("Usuario nao encontrado");
        }

        const userWithUpdatedEmail = await database.get("SELECT * FROM users WHERE email = (?)", [email]);

        if(userWithUpdatedEmail && userWithUpdatedEmail.id !== user.id){
            throw new AppError(" Esse email ja esta em uso por outro usuario ");
        }

        if (!old_password) {
            throw new AppError("A senha antiga deve ser informada");
        }

        if (password && old_password) {
            const checkOldPassword = await compare(old_password, user.password);
            if(!checkOldPassword) {
                throw new AppError("A senha antiga nao confere.");
            }

            user.password = await hash(password, 8);
        }

        user.name = name ?? user.name;
        user.email = email ?? user.email;

        await database.run(`
        UPDATE users SET
        name = ?,
        email = ?,
        password = ?,
        updated_at = DATETIME('now')
        WHERE id = ?`,
        [user.name, user.email, user.password, id]
        );

        return response.status(200).json();
    }
}

module.exports = UsersController;