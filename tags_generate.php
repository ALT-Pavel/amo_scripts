<?
// получение токена
function getAccessToken()
{
    $clientId = 'you_integration_id';
    $clientSecret = 'you_secret_key';
    $redirectUri = 'you_url';
    $authorizationCode = 'you_code'; //20 min active

    $link = "https://you_subdomain.amocrm.ru/oauth2/access_token";

    $data = [
        'client_id' => $clientId,
        'client_secret' => $clientSecret,
        'grant_type' => 'authorization_code',
        'code' => $authorizationCode,
        'redirect_uri' => $redirectUri
    ];

    $headers = ['Content-Type:application/json'];

    $response = sendCurlRequest($link, $data, $headers);
    $tokens = json_decode($response, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        logError("Ошибка декодирования JSON: " . json_last_error_msg());
        return null;
    }

    if (isset($tokens['access_token']) && isset($tokens['refresh_token'])) {
        file_put_contents(__DIR__ . '/tokens.json', json_encode($tokens));
        return $tokens['access_token'];
    }

    logError("Не удалось получить access token. Response: $response");
    return null;
}

// Обновления токена
function refreshAccessToken()
{
    $clientId = 'you_integration_id';
    $clientSecret = 'you_secret_key';
    $redirectUri = 'you_url';

    $tokens = json_decode(file_get_contents(__DIR__ . '/tokens.json'), true);
    $refreshToken = $tokens['refresh_token'];

    $link = "https://you_subdomain.amocrm.ru/oauth2/access_token";

    $data = [
        'client_id' => $clientId,
        'client_secret' => $clientSecret,
        'grant_type' => 'refresh_token',
        'refresh_token' => $refreshToken,
        'redirect_uri' => $redirectUri
    ];

    $headers = ['Content-Type:application/json'];

    $response = sendCurlRequest($link, $data, $headers);
    $tokens = json_decode($response, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        logError("Ошибка декодирования JSON: " . json_last_error_msg());
        return null;
    }

    if (isset($tokens['access_token']) && isset($tokens['refresh_token'])) {
        file_put_contents(__DIR__ . '/tokens.json', json_encode($tokens));
        return $tokens['access_token'];
    }

    logError("Ошибка обновления токена. Response: $response");
    return null;
}

function getAccessTokenFromFile()
{
    $tokens = json_decode(file_get_contents(__DIR__ . '/tokens.json'), true);
    return $tokens['access_token'];
}

//проверка токена
function getValidAccessToken()
{
    $accessToken = getAccessTokenFromFile();

    $isValid = checkAccessTokenValidity($accessToken);

    if (!$isValid) {
        $accessToken = refreshAccessToken();
        if (!$accessToken) {
            logError("Невозможно получить валидный токен");
            exit("Unable to get valid token");
        }
    }

    return $accessToken;
}

// Отправка curl-запросов
function sendCurlRequest($url, $data, $headers = [], $customRequest = 'POST')
{
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_USERAGENT, 'amoCRM-oAuth-client/1.0');
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($curl, CURLOPT_HEADER, false);
    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $customRequest);
    curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 1);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);

    $response = curl_exec($curl);
    $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    if ($httpCode < 200 || $httpCode > 204) {
        logError("Ошибка выполнения запроса. HTTP Code: $httpCode. Response: $response");
        return null;
    }

    return $response;
}

// Получение данных из вебхука
function getWebhookData()
{
    return json_encode($_POST);
}

// Извлечение id сделки из вебхука
function extractDealId($webhookData)
{
    $webhookData = json_decode($webhookData, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        logError("Ошибка декодирования JSON: " . json_last_error_msg());
        return null;
    }

    if (isset($webhookData['leads']['status'][0]['id'])) {
        return $webhookData['leads']['status'][0]['id'];
    } elseif (isset($webhookData['leads']['add'][0]['id'])) {
        return $webhookData['leads']['add'][0]['id'];
    }

    return null;
}

// Получение данных сделки
function getDealDataFromAmoCRM($dealId, $subdomain, $accessToken)
{
    $url = "https://$subdomain.amocrm.ru/api/v4/leads/$dealId";
    $headers = [
        'Authorization: Bearer ' . $accessToken,
        'Content-Type: application/json'
    ];

    $response = sendCurlRequest($url, [], $headers, 'GET');

    if ($response === null) {
        return null;
    }

    $dealData = json_decode($response, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        logError("Ошибка декодирования JSON: " . json_last_error_msg());
        return null;
    }

    $extractedData = [
        'id' => $dealData['id'] ?? '',
        'order' => 'нет данных',
        'deadline' => 'нет данных'
    ];

    foreach ($dealData['custom_fields_values'] as $field) {
        if ($field['field_id'] == 494783) {
            $extractedData['order'] = $field['values'][0]['value'] ?? 'нет данных';
        }
        if ($field['field_id'] == 495986) {
            $extractedData['deadline'] = isset($field['values'][0]['value']) ? date('d/m/Y', $field['values'][0]['value']) : 'нет данных';
        }
    }

    return $extractedData;
}

// Генерация HTML-страницы по шаблону
function generateHtmlPage($dealData)
{
    $template = file_get_contents('file.html');
    $htmlContent = str_replace(
        ['{{number}}', '{{order}}', '{{deadline}}'],
        [$dealData['id'], $dealData['order'], $dealData['deadline']],
        $template
    );

    $fileName = 'filename_' . $dealData['id'] . '.html';
    $filePath = __DIR__ . '/../amo_tags/' . $fileName;
    file_put_contents($filePath, $htmlContent);

    return $filePath;
}

// Обновление имени сделки
function updateDealName($dealId, $newDealName, $subdomain, $accessToken)
{
    $url = "https://$subdomain.amocrm.ru/api/v4/leads/$dealId";

    $data = [
        'name' => $newDealName
    ];

    $headers = [
        'Authorization: Bearer ' . $accessToken,
        'Content-Type: application/json'
    ];

    $response = sendCurlRequest($url, $data, $headers, 'PATCH');

    if ($response === null) {
        return null;
    }

    return json_decode($response, true);
}

// Отправка ссылки на файл в amoCRM
function sendLinkToAmoCrm($filePath, $dealId, $fieldId, $subdomain, $accessToken)
{
    $link = 'http://' . $_SERVER['SERVER_NAME'] . '/path/' . basename($filePath);

    $url = "https://$subdomain.amocrm.ru/api/v4/leads/$dealId";
    $data = [
        'custom_fields_values' => [
            [
                'field_id' => $fieldId,
                'values' => [
                    [
                        'value' => $link
                    ]
                ]
            ]
        ]
    ];

    $headers = [
        'Authorization: Bearer ' . $accessToken,
        'Content-Type: application/json'
    ];

    $response = sendCurlRequest($url, $data, $headers, 'PATCH');

    if ($response === null) {
        return null;
    }

    return json_decode($response, true);
}

// Логирование ошибок
function logError($message)
{
    $logFile = __DIR__ . '/error.log';
    $date = date('Y-m-d H:i:s');
    $logMessage = "[$date] ERROR: $message" . PHP_EOL;
    file_put_contents($logFile, $logMessage, FILE_APPEND);
}

// Основной процесс
$webhookData = getWebhookData();

if ($webhookData) {
    $dealId = extractDealId($webhookData);
    $fieldId = 'id';
    $subdomain = 'subdomain';
    $accessToken = getValidAccessToken();

    if ($dealId) {
        $dealData = getDealDataFromAmoCRM($dealId, $subdomain, $accessToken);
        $newDealName = 'Сделка #' . $dealId;
        $updateResponse = updateDealName($dealId, $newDealName, $subdomain, $accessToken);
        $fileName = generateHtmlPage($dealData);
        $response = sendLinkToAmoCrm($fileName, $dealId, $fieldId, $subdomain, $accessToken);
    } else {
        logError("Не получен id сделки");
    }
} else {
    logError("Не получены данные из вебхука");
}
