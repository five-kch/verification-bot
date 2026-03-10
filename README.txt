1. Создай новый репозиторий на GitHub.
2. Добавь туда файлы: bot.py, requirements.txt, .env.example, .gitignore.
3. На Railway создай New Project -> Deploy from GitHub.
4. В Variables добавь:
   BOT_TOKEN=...
   PROTECTED_CHAT_ID=-1001916510076
   OWNER_ID=...
5. Добавь бота админом в группу.
6. Выдай права: Restrict members, Ban users, Delete messages.
7. Проверь, что у бота включены allowed_updates для chat_member и message_reaction.

Главные команды:
/start
/status
/idgate_status
/idgate_set 7000000000
/idgate_up 1000000
/idgate_down 1000000
/rules_status
/rules_setchat -1001916510076
/rules_setmsg 2151
/rules_setemoji 👍
/antispam_on
/antispam_off
/logs 20
/logs_user 123456789 20
/reset_attempts 123456789
/unban 123456789

Логика ID-gate:
- user_id < threshold -> сразу капча
- user_id >= threshold -> 1-я и 2-я попытка кик
- 3-я-12-я попытка -> капча
- 13-я попытка -> бан на 24 часа
- если anti-spam включён, user_id >= threshold -> кик на каждой попытке, на 13-й бан на 24 часа

Логика верификации:
- при входе бот сразу ограничивает права
- капча действует 60 секунд
- после капчи пользователь должен поставить нужный эмодзи под публикацией
- до эмодзи-подтверждения права не открываются