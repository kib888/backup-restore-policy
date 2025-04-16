import os
import json
import time
import asyncio
import aiohttp
import uuid

'''Вспомогательные функции и глобальные переменные'''
def load_credentials(file_path):
    credentials = {}
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line: 
                key, value = line.split('=', 1) 
                key = key.strip()  
                credentials[key] = value            
    return credentials

creds = load_credentials('creds.txt')
url_backup_api = f'https://{creds["BACKUP_HOST"]}/api/ptaf/v4'
url_restore_api = f'https://{creds["RESTORE_HOST"]}/api/ptaf/v4'

async def fetch_data(url, headers):
    # Создаем сессию с отключенной проверкой SSL
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        async with session.get(url, headers=headers) as response:
            # Получаем текст ответа
            return await response.json()

async def post_data(url, payload):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        async with session.post(url, json=payload) as response:
            return await response.json()

async def post_with_headers_data(url, headers, payload):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        async with session.post(url, headers=headers, json=payload) as response:
            return await response.json()
  
async def patch_data(url, headers, payload):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        async with session.patch(url, headers=headers, json=payload) as response:
            return await response.json()

async def fetch_and_save_file(url, headers, save_path):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        async with session.get(url, headers=headers) as response:
            # Проверяем, что запрос был успешным
            if response.status == 200:
                # Читаем содержимое ответа
                content = await response.text()
                # Разделяем содержимое на строки и убираем лишние пустые строки
                lines = [line.strip() for line in content.splitlines() if line.strip()]
                # Сохраняем содержимое в файл
                with open(save_path, 'w', encoding='utf-8') as file:
                    file.write('\n'.join(lines))                
            else:
                print(f"Ошибка при запросе: {response.status}")

async def get_headers(host,user,password):    
    login_url = f'https://{host}/api/ptaf/v4/auth/refresh_tokens'
    # Получение токена авторизации
    login_data = {"username": f'{user}',"password": f'{password}',"fingerprint": "testuser"}
    response_data = await post_data(login_url, login_data)
    access_token = response_data.get('access_token')
    headers= {
        'Accept': 'application/json',
        'Authorization': f'Bearer {access_token}'
        }
    return headers

async def get_token(host,user,password):
    
    login_url = f'https://{host}/api/ptaf/v4/auth/refresh_tokens'

    # Получение токена авторизации
    login_data = {"username": f'{user}',"password": f'{password}',"fingerprint": "testuser"}
    response_data = await post_data(login_url, login_data)
    access_token = response_data.get('access_token')
    return access_token

def read_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    return data

def find_key_by_value(dictionary, target_value):
    for key, value in dictionary.items():
        if value == target_value:
            return key


'''Получение шаблонов, правил из шаблонов'''
async def get_template_name(id, headers, owner):
    url = f"{url_backup_api}/config/policies/templates/{owner}/{id}"
    response_data = await fetch_data(url, headers=headers)
    return response_data['name']

async def get_user_templates(urlapi, headers):
    url = f'{urlapi}/config/policies/templates/user'
    response_data = await fetch_data(url, headers=headers)

    result_list = []
    
    for item in response_data['items']:
        response_data = await fetch_data(f"{url}/{item['id']}", headers=headers)
        result_list.append(response_data)
    list_for_save = []
    for item in result_list:
        template_based_name = await get_template_name(item['templates'][0], headers, 'vendor')
        list_for_save.append({
            'name': item['name'],
            "has_user_rules": item["has_user_rules"],
            "based_on_name": template_based_name 
        }
        )
    os.makedirs("backup", exist_ok=True)
    with open("backup/templates.json", 'w', encoding='utf-8') as file:
        json.dump(list_for_save, file, indent=4, ensure_ascii=False)
    return result_list    

async def get_rules_for_template(item, headers):
    """Функция для сбора правил для одного шаблона."""
    url = f"{url_backup_api}/config/policies/templates/user/{item['id']}/rules"
    print(f"Собираем изменённые правила для шаблона {item['name']}...")
    response_data = await fetch_data(url, headers=headers)
    actions_list = await get_actions_name(headers)
    dict_names = await get_global_lists_names(headers)
    rules_for_template = []  # Список для хранения правил текущего шаблона
    
    for i in response_data['items']:
        url = f"{url_backup_api}/config/policies/templates/user/{item['id']}/rules/{i['id']}"
        url_ui = f"https://{creds['BACKUP_HOST']}/conf-scheme/user_policy/{item['id']}/rules/rule/{i['id']}"
        response_data = await fetch_data(url, headers=headers)

        if response_data['has_overrides'] and response_data['is_system']:
            actions = [actions_list.get(id) for id in response_data['actions']]
            params_with_list_names = replace_value_with_name(response_data['variables'], dict_names)
            rules_for_template.append({
                'rule_name': response_data['name'],
                'rule_link': url_ui,
                'is_active': response_data['enabled'],
                'actions': actions,
                'variables': params_with_list_names
            })  # Добавляем правило в список
    
    # Если у шаблона есть правила, возвращаем их
    if rules_for_template:
        url_ui_template = f"https://{creds['BACKUP_HOST']}/conf-scheme/vendor_policy/{item['templates'][0]}"
        template_based_name = await get_template_name(item['templates'][0], headers, 'vendor')
        return {
            "template_name": item['name'],  # Имя шаблона
            "based_on_name": template_based_name, # На чём основан
            "based_on_link": url_ui_template,
            ""   
            "rules": rules_for_template  # Список правил для этого шаблона
        }

async def get_rules_template(user_templates, headers):
    """Основная функция для сбора правил для всех шаблонов."""
    json_data = user_templates
    
    # Запускаем задачи для каждого шаблона параллельно
    tasks = [get_rules_for_template(item, headers) for item in json_data]
    grouped_rules = await asyncio.gather(*tasks)

    # Создаем директорию, если она не существует
    os.makedirs("backup", exist_ok=True)

    # Записываем данные в файл
    with open("backup/template_rules.json", 'w', encoding='utf-8') as file:
        json.dump(grouped_rules, file, indent=4, ensure_ascii=False)

    print("Сбор правил для шаблонов завершён.")


'''Получение политик, правил из политик'''

async def get_user_policy(urlapi, headers):
    url = f'{urlapi}/config/policies'
    response_data = await fetch_data(url, headers=headers)

    result_list = []
    
    for item in response_data['items']:
        response_data = await fetch_data(f"{url}/{item['id']}", headers=headers)
        result_list.append(response_data)

    return result_list    

async def get_rules_for_policy(item,headers):
    """Функция для сбора правил для одного шаблона."""
    url = f"{url_backup_api}/config/policies/{item['id']}/rules"
    print(f"Собираем изменённые правила для политики {item['name']}...")
    response_data = await fetch_data(url, headers=headers)
    actions_list = await get_actions_name(headers)
    dict_names = await get_global_lists_names(headers)
    rules_for_policy = []  # Список для хранения правил текущего шаблона
    
    for i in response_data['items']:
        url = f"{url_backup_api}/config/policies/{item['id']}/rules/{i['id']}"
        url_ui = f"https://{creds['BACKUP_HOST']}/conf-scheme/application_policy/{item['id']}/rules/rule/{i['id']}"
        response_data = await fetch_data(url, headers=headers)        
        if response_data['has_overrides'] and response_data['is_system']:
            actions = [actions_list.get(id) for id in response_data['actions']]
            params_with_list_names = replace_value_with_name(response_data['variables'], dict_names)
            rules_for_policy.append({
                'rule_name': response_data['name'],
                'rule_link': url_ui,
                'is_active': response_data['enabled'],
                'actions': actions,
                'variables': params_with_list_names  
                })  # Добавляем правило в список
    
    # Если у шаблона есть правила, возвращаем их
    if rules_for_policy:
        url_ui_template = f"https://{creds['BACKUP_HOST']}/conf-scheme/user_policy/{item['template_id']}"
        template_based_name = await get_template_name(item['template_id'], headers, "user")
        return {
            "policy_name": item['name'], # Имя шаблона
            "based_on_name": template_based_name,
            "based_on_link": url_ui_template,    #На чём основан
            "rules": rules_for_policy     # Список правил для этого шаблона
        }

async def get_rules_policy(policies, headers):
    """Основная функция для сбора правил для всех шаблонов."""
    json_data = policies
    
    # Запускаем задачи для каждого шаблона параллельно
    tasks = [get_rules_for_policy(item, headers) for item in json_data]
    grouped_rules = await asyncio.gather(*tasks)

    # Создаем директорию, если она не существует
    os.makedirs("backup", exist_ok=True)

    # Записываем данные в файл
    with open("backup/policy_rules.json", 'w', encoding='utf-8') as file:
        json.dump(grouped_rules, file, indent=4, ensure_ascii=False)

    print("Сбор правил для политик завершён.")


'''Получение глобальных списков'''
async def get_ip_from_list(headers, id, name):
    url = f"{url_backup_api}/config/global_lists/{id}/file"
    await fetch_and_save_file(url, headers, name)

async def get_global_lists(headers):
    url = f"{url_backup_api}/config/global_lists"
    os.makedirs("backup/global_lists", exist_ok=True)
    lists = []
    response_data = await fetch_data(url, headers=headers)
    #print(response_data)
    for item in response_data['items']:
        if item['type'] == 'STATIC':
           await get_ip_from_list(headers, item['id'], f"backup/global_lists/{item['name']}") 
        lists.append({
            'list_name': item['name'],
            'list_type': item['type']
        }
        )
    # Записываем данные в файл
    with open("backup/global_lists/global_lists.json", 'w', encoding='utf-8') as file:
        json.dump(lists, file, indent=4, ensure_ascii=False)

    print("Сбор глобальных списков завершён.")    

async def get_global_lists_names(headers):
    url = f"{url_backup_api}/config/global_lists"
    response_data = await fetch_data(url, headers)
    id_to_name = {item['id']: item['name'] for item in response_data['items']}
    return id_to_name

def replace_value_with_name(data, id_to_name):
    # Создаем копию данных, чтобы не изменять исходный JSON
    data = data.copy() if isinstance(data, dict) else data[:] if isinstance(data, list) else data

    if isinstance(data, dict):
        # Если в словаре есть ключ 'global_param_type', заменяем 'value' на имя из словаря
        if 'global_param_type' in data:
            value = data.get('value')
            if isinstance(value, list):
                # Если value — это список, обрабатываем каждый элемент
                data['value'] = [id_to_name.get(item, item) for item in value]
            elif isinstance(value, str):
                # Если value — это строка, заменяем её, если она есть в словаре
                data['value'] = id_to_name.get(value, value)
            return data  # Возвращаем измененный JSON
        
        # Рекурсивно обходим все значения в словаре
        for key, value in data.items():
            data[key] = replace_value_with_name(value, id_to_name)
        return data  # Возвращаем JSON после рекурсивной обработки
    
    elif isinstance(data, list):
        # Рекурсивно обходим все элементы списка
        for i, item in enumerate(data):
            data[i] = replace_value_with_name(item, id_to_name)
        return data  # Возвращаем JSON после рекурсивной обработки
    
    else:
        # Если данные не являются словарем или списком, возвращаем их без изменений
        return data


'''Получение действий'''
async def get_user_actions(headers):
    url = f"{url_backup_api}/config/actions"
    os.makedirs("backup", exist_ok=True)
    user_action = []
    dict_action_type_name = await get_action_type_name(headers)
    response_data = await fetch_data(url, headers)
    for item in response_data['items']:
        if not item['is_system']:
            actions_type_name = dict_action_type_name.get(item['type_id'])
            user_action.append({
                'action_name': item['name'],
                'action_type': actions_type_name,
                'action_params': item['params']
            })
    with open("backup/user_actions.json", 'w', encoding='utf-8') as file:
        json.dump(user_action, file, indent=4, ensure_ascii=False)
    print("Сбор пользовательских действий завершен")

async def get_action_type_name(headers, url_api=url_backup_api):
    url = f"{url_api}/config/action_types"
    response_data = await fetch_data(url, headers)
    id_to_name = {item['id']: item['name'] for item in response_data['items']}
    return id_to_name

async def get_actions_name(headers, url_api=url_backup_api):
    url = f"{url_api}/config/actions"
    response_data = await fetch_data(url, headers)
    id_to_name = {item['id']: item['name'] for item in response_data['items']}
    return id_to_name


'''Восстановление действий '''
async def restore_user_actions(headers):
    url = f"{url_restore_api}/config/actions"
    user_actions = read_json('backup/user_actions.json')
    dict_types_name = await get_action_type_name(headers, url_restore_api)
    for i in user_actions:
        id_action_type = find_key_by_value(dict_types_name, i['action_type'])
        data = {
            "type_id": id_action_type,
            "name": i['action_name'],
            "params": i['action_params']
        }
        await post_with_headers_data(url, headers, data)
    print('Пользовательские действия импортированы')

 
'''Восстановление списков'''
async def restore_global_lists(headers):
    url = f"{url_restore_api}/config/global_lists"
    global_lists = read_json('backup/global_lists/global_lists.json')
    
    for i in global_lists:      
        if i['list_type'] == "STATIC":
            file = open(f"backup/global_lists/{i['list_name']}", "rb")
            data = aiohttp.FormData()
            data.add_field("name", i['list_name'])
            data.add_field("type", i['list_type'])
            data.add_field(
                "file",  
                file,  
                filename=i['list_name'],  
                content_type="text/plain" 
            )                
            
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                try:                    
                    # Отправка запроса
                    async with session.post(url, headers=headers, data=data) as response:
                        if response.status == 201:
                            print(f"{i['list_name']} загружен.")
                        else:
                            if response.status == 422:
                                print(f"Статус: {response.status} {i['list_name']} не загружен, не уникальный")
                            #print(await response.text())  # Вывод ошибки сервера
                finally:
                    file.close()
        else:
            boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
            token = headers.get('Authorization')
            head = {
                "Authorization": f"{token}",
                "Content-Type": f"multipart/form-data; boundary={boundary}"
            }

            body = (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="name"\r\n\r\n'
                f"{i['list_name']}\r\n"
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="type"\r\n\r\n'
                f"{i['list_type']}\r\n"
                f"--{boundary}--\r\n"
            )
            
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:                                
                # Отправка запроса
                async with session.post(url, headers=head, data=body) as response:
                    if response.status == 201:
                        print(f"{i['list_name']} загружен.")
                    else:
                        if response.status == 422:
                            print(f"Статус: {response.status} {i['list_name']} не загружен, не уникальный")
                        #print(await response.text())  # Вывод ошибки сервера
    await post_with_headers_data(f"{url_restore_api}/config/global_lists/apply", headers, payload='')
    print('Пользовательские списки импортированы')


'''Восстановление шаблонов'''
async def get_template_id_name(headers, owner):
    url = f"{url_restore_api}/config/policies/templates/{owner}"
    response_data = await fetch_data(url, headers=headers)
    dict_id_name = {item['id']: item['name'] for item in response_data['items']}
    return dict_id_name

async def restore_templates(headers):
    url = f"{url_restore_api}/config/policies/templates/user"
    templates = read_json('backup/templates.json')
    dict_id_name = await get_template_id_name(headers, 'vendor')
    for i in templates:
        data = {
            'name': i['name'],
            'templates': [find_key_by_value(dict_id_name, i['based_on_name'])],
            'has_user_rules': i['has_user_rules']  
        }
        await post_with_headers_data(url, headers, data)
    print("Пользовательские шаблоны импортированы")


'''Восстановление правил для шаблонов'''
async def get_dict_system_rules(headers):
    dict_template_id_name = await get_template_id_name(headers, 'vendor')
    id1 = list(dict_template_id_name.keys())[0]
    url = f"{url_restore_api}/config/policies/templates/vendor/{id1}/rules"
    response_data = await fetch_data(url, headers)
    dict_rules_id_name = {item['id']: item['name'] for item in response_data['items']}
    return dict_rules_id_name

async def get_dict_list_id_name(headers, url_api):
    url = f"{url_api}/config/global_lists"
    response_data = await fetch_data(url, headers)
    id_to_name = {item['id']: item['name'] for item in response_data['items']}
    return id_to_name

async def restore_templates_rules(headers):
    templates_rules = read_json('backup/template_rules.json')
    templates_dict_id_name = await get_template_id_name(headers, 'user')
    rules_dict_id_name = await get_dict_system_rules(headers)
    actions_dict_id_name = await get_actions_name(headers, url_restore_api)
    list_dict_id_name = await get_dict_list_id_name(headers, url_restore_api)
    list_dict_name_id = {value: key for key, value in list_dict_id_name.items()}

    for template in templates_rules:
        template_id = find_key_by_value(templates_dict_id_name, template['template_name'])
        for rule in template['rules']:
            rule_id = find_key_by_value(rules_dict_id_name, rule['rule_name'])
            actions = []
            for action in rule['actions']:
                actions.append(find_key_by_value(actions_dict_id_name, action))
            params_with_list_ids = replace_value_with_name(rule['variables'], list_dict_name_id)            
            data = {
                "actions": actions,
                "variables": params_with_list_ids,
                "enabled": rule['is_active']
            }
            url = f"{url_restore_api}/config/policies/templates/user/{template_id}/rules/{rule_id}"
            await patch_data(url, headers, data)
        print(f'Правила для шаблона {template["template_name"]} восстановлены')
    print('Правила во всех шаблонах восстановлены')


'''Восстановление политики'''
async def restore_policies(headers):
    url = f"{url_restore_api}/config/applications"
    policies = read_json('backup/policy_rules.json')
    dict_id_name = await get_template_id_name(headers, 'user')
    for i in policies:
        if i is not None:
            data = {
                'name': i['policy_name'],
                "protection_mode": "PASSIVE",
                "hosts": [],
                "locations": ["/"],
                'policy_template_id': find_key_by_value(dict_id_name, i['based_on_name']),
                "traffic_profiles": []
            }
            await post_with_headers_data(url, headers, data)
            
    print("Пользовательские приложения импортированы")


'''Восстановление правил для политики'''
async def get_policies_id_name(headers):
    url = f"{url_restore_api}/config/policies"
    response_data = await fetch_data(url, headers=headers)
    dict_id_name = {item['id']: item['name'] for item in response_data['items']}
    return dict_id_name

async def restore_policies_rules(headers):
    policies_rules = read_json('backup/policy_rules.json')
    policies_dict_id_name = await get_policies_id_name(headers)
    rules_dict_id_name = await get_dict_system_rules(headers)
    actions_dict_id_name = await get_actions_name(headers, url_restore_api)
    list_dict_id_name = await get_dict_list_id_name(headers, url_restore_api)
    list_dict_name_id = {value: key for key, value in list_dict_id_name.items()}


    for policy in policies_rules:
        if policy is not None:
            policy_id = find_key_by_value(policies_dict_id_name, policy['policy_name'])
            for rule in policy['rules']:
                rule_id = find_key_by_value(rules_dict_id_name, rule['rule_name'])
                actions = []
                for action in rule['actions']:
                    actions.append(find_key_by_value(actions_dict_id_name, action))
                params_with_list_ids = replace_value_with_name(rule['variables'], list_dict_name_id)            
                data = {
                    "actions": actions,
                    "variables": params_with_list_ids,
                    "enabled": rule['is_active']
                }
                url = f"{url_restore_api}/config/policies/{policy_id}/rules/{rule_id}"
                await patch_data(url, headers, data)
            print(f'Правила для политики {policy["policy_name"]} восстановлены')
    print('Правила во всех политиках восстановлены')


'''Главная функция бекапа'''
async def backup():
    start_time = time.time()
    
    headers = await get_headers(creds['BACKUP_HOST'], creds['BACKUP_USERNAME'], creds['BACKUP_PASSWORD'])

    # Запускаем задачи параллельно
    templates, policies = await asyncio.gather(
        get_user_templates(url_backup_api, headers),
        get_user_policy(url_backup_api, headers)
    )

    await asyncio.gather(
        get_rules_template(templates, headers),
        get_rules_policy(policies, headers),
        get_global_lists(headers),
        get_user_actions(headers)

    )

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Время выполнения: {execution_time:.2f} секунд")
    print('Бекап готов! Смотрите директорию backup')


'''Главная функция восстановления'''

async def restore():
    start_time = time.time()
    headers = await get_headers(creds['RESTORE_HOST'], creds['RESTORE_USERNAME'], creds['RESTORE_PASSWORD'])
    
    await restore_user_actions(headers)
    await restore_global_lists(headers)
    await restore_templates(headers)
    

    await restore_templates_rules(headers)
    await restore_policies(headers)
    await restore_policies_rules(headers)

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Восстановление завершено! Время выполнения: {execution_time:.2f} секунд")

if __name__ == "__main__":
    print('ПРОВЕРЬТЕ КОРРЕКТНОСТЬ ЗАПОЛНЕНИЯ CREDS.TXT!!! ЕСЛИ ПРЕПУТАТЬ, ВСЁ МОЖЕТ СЛОМАТЬСЯ В СОХРАНЯЕМОМ ТЕНАНТЕ!!!')
    try:
        mode = input('Вы хотите сделать бекап(1), восстановиться из бекапа(2), или и то и другое(3)? Введите число: ')
        match int(mode):
            case 1:
                asyncio.run(backup())
            case 2:
                asyncio.run(restore())
            case 3:
                asyncio.run(backup())
                asyncio.run(restore())
            case _:
                print("Как можно было лажануть в выборе из трёх цифр?")
    except Exception as e:
        print(f'Fatal error:\n{e}')