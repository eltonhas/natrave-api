import { PrismaClient } from "@prisma/client"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"

const prisma = new PrismaClient()

export const create = async ctx => {

    const password = await bcrypt.hash(ctx.request.body.password, 10) 

    const data = {
        name: ctx.request.body.name,
        username: ctx.request.body.username,
        email: ctx.request.body.email,
        password,
    }

    try {
        const { password, ...result } = await prisma.user.create({ data })

        // Codificar as informações e criar o token
        const accessToken = jwt.sign({
            sub: result.id,
            name: result.name,
            expiresIn: "7d"
        }, process.env.JWT_SECRET)

        ctx.body = {
            user: result,
            accessToken
        }
        ctx.status = 201

    } catch (error) {
        console.log(error)
        ctx.body = error
        ctx.status = 500
    }
}
export const login = async ctx => {
    // Pegar o token do cabeçalho de autenticação da requisição e separa
    const [type, token] = ctx.headers.authorization.split(" ")
    // Faz o decode do cabeçalho
    const decodedToken = atob(token)
    // Guardar as informações do cabeçalho
    const [email, plainTextPassword] = decodedToken.split(":")
    
    const user = await prisma.user.findUnique({
        where: { email }
    })

    if (!user) {
        ctx.status = 404
        return
    }

    const passwordMatch = await bcrypt.compare(plainTextPassword, user.password)

    if (!passwordMatch) {
        ctx.status = 404
        return
    }

    const { password, ...result } = user

    // Codificar as informações e criar o token
    const accessToken = jwt.sign({
        sub: user.id,
        name: user.name,
        expiresIn: "7d"
    }, process.env.JWT_SECRET)

    ctx.body = {
        user: result,
        accessToken
    }

    ctx.status = 200
}

export const hunches = async ctx => {
    const username = ctx.request.params.username

    const user = await prisma.user.findUnique({
        where: { username }
    })

    if (!user) {
        ctx.status = 404
        return
    }

    const hunches = await prisma.hunch.findMany({
        where: {
            userId: user.id
        }
    })

    ctx.body = {
        name: user.name,
        hunches
    }

}