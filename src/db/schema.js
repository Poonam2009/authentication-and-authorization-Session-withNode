import { text, pgTable, varchar, uuid, timestamp, pgEnum } from "drizzle-orm/pg-core";

export const userRoleEnum = pgEnum("user_role", ["USER", "ADMIN"]);

export const usersTable = pgTable("users", {
  id: uuid().primaryKey().defaultRandom(),
  name: varchar({ length: 255 }).notNull(),
  email: varchar({ length: 255 }).notNull().unique(),
  role: userRoleEnum().notNull().default("USER"),
  password: text().notNull(),
  salt: text().notNull()
});

export const userSession = pgTable("user_session", {
    id: uuid().primaryKey().defaultRandom(),
    userId: uuid().references(() => usersTable.id).notNull(),
    createAt: timestamp().defaultNow().notNull()
})