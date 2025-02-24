import { verify } from "hono/jwt";
import { Context, Next } from "hono";

export const authMiddleware = async (c: Context, next: Next) => {
  try {
    const authHeader = c.req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Token ausente ou inválido" }, 401);
    }

    const token = authHeader.split(" ")[1];
    const db = c.env.DB;

    // Verifica se o token existe no banco
    const sessionResult = await db.prepare(
      "SELECT user_id, expires_at FROM sessions WHERE token = ?"
    ).bind(token).first();

    const session = sessionResult as { user_id: string; email: string; expires_at: string } | null;

    if (!session || new Date(session.expires_at) < new Date()) {
      return c.json({ error: "Sessão expirada ou inválida." }, 401);
    }

    // Verifica o token JWT
    const payload = await verify(token, c.env.JWT_SECRET) as { userId: string; email: string };

    if (!payload || !payload.userId) {
      return c.json({ error: "Token JWT inválido." }, 401);
    }

    c.set("jwtPayload", payload);
    await next();
  } catch (error) {
    console.error("Erro na autenticação:", error);
    return c.json({ error: "Erro na autenticação." }, 401);
  }
};