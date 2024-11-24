<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';

$app = new \Slim\App;

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "library";
$key = 'cattocattocatto123^-^!';


// Create a global PDO connection
try {
    $pdo = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}


// Middleware to check JWT token stored in httpOnly cookies
$jwtMiddleware = function (Request $request, Response $response, $next) {
    $cookies = $request->getCookieParams();
    $token = $cookies['auth_token'] ?? '';

    if ($token) {
        try {
            $decoded = JWT::decode($token, new Key($GLOBALS['key'], 'HS256'));
            $request = $request->withAttribute('jwt', $decoded);
            
            // Proceed with the request
            $response = $next($request, $response);

            // After the action, generate a new token and set the cookie
            $username = $decoded->data->username;
            $newToken = createJWT($username, $GLOBALS['key']);
            $cookie = 'auth_token=' . $newToken . '; Path=/; HttpOnly; SameSite=Strict;';
            
            return $response->withHeader('Set-Cookie', $cookie);
        } catch (Exception $e) {
            $response->getBody()->write(json_encode(["status" => "failed", "message" => "Unauthorized: " . $e->getMessage()]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }
    } else {
        $response->getBody()->write(json_encode(["status" => "failed", "message" => "Token not provided"]));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }
};


// Helper function to create JWT token
function createJWT($username, $key) {
    $expire = time();
    $payload = [
        'iss' => 'http://cit.dmmmsu.gov.ph',
        'aud' => 'http://cit.elibrary.gov.ph',
        'iat' => $expire,
        'exp' => $expire + (60 * 60), // Token expiration set to 1 hour
        'data' => ['username' => $username]
    ];
    return JWT::encode($payload, $key, 'HS256');
}


// User Registration (no token required) | Working
$app->post('/user/register', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname, $key;
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $checkQuery = "SELECT * FROM users WHERE username = :username";
        $checkStmt = $conn->prepare($checkQuery);
        $checkStmt->execute(['username' => $uname]);

        if ($checkStmt->rowCount() > 0) {
            $response->getBody()->write(json_encode(["status" => "error", "message" => "Username already taken"]));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        // Insert new user
        $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['username' => $uname, 'password' => hash('SHA256', $pass)]);

        // Create JWT token
        $token = createJWT($uname, $key);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Registration Successful", "token" => $token]));
        return $response->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    }
});




// User Login with Authentication (no token required) 
$app->post('/user/login', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname, $key;
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch user by username and password
        $sql = "SELECT * FROM users WHERE username = :username AND password = :password";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['username' => $uname, 'password' => hash('SHA256', $pass)]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Check if user is disabled
            if ($user['status'] === 'disabled') {
                $response->getBody()->write(json_encode(["status" => "failed", "message" => "Your account has been disabled. Please contact the admin to reactivate your account."]));
                return $response->withStatus(403)->withHeader('Content-Type', 'application/json'); // Forbidden status
            }

            // Create JWT token
            $token = createJWT($uname, $key);

            // Store the token in httpOnly cookie
            $cookie = 'auth_token=' . $token . '; Path=/; HttpOnly; SameSite=Strict;';
            $response->getBody()->write(json_encode(["status" => "success", "message" => "Login successful"]));
            return $response->withHeader('Set-Cookie', $cookie)->withHeader('Content-Type', 'application/json');
        } else {
            $response->getBody()->write(json_encode(["status" => "failed", "message" => "Authentication failed"]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "failed", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    }
});


//User View Book List
$app->get('/books', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname, $key;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch only non-archived books with their authors
        $query = "SELECT b.bookid, b.title, a.name AS author
                  FROM books b
                  JOIN authors a ON b.authorid = a.authorid
                  WHERE b.archived = 0"; // Ensure only unarchived books are fetched

        $stmt = $conn->prepare($query);
        $stmt->execute();
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Generate a new token for the user
        $jwt = $request->getAttribute('jwt');
        $username = $jwt->data->username;
        $newToken = createJWT($username, $key);

        // Set the new token in the httpOnly cookie
        $cookie = 'auth_token=' . $newToken . '; Path=/; HttpOnly; SameSite=Strict;';

        // Check if books are available
        if (empty($books)) {
            $response->getBody()->write(json_encode(["status" => "success", "message" => "No Books Available"]));
        } else {
            $response->getBody()->write(json_encode($books));
        }

        return $response->withHeader('Set-Cookie', $cookie)
                        ->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    }
})->add($jwtMiddleware);


// User View Specific Book
$app->get('/books/{bookid}', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname, $key;

    // Retrieve bookid from the URL
    $bookid = $args['bookid'];

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch the book with the specified bookid, ensuring it's not archived
        $query = "SELECT b.title, a.name AS author, b.content
                  FROM books b
                  JOIN authors a ON b.authorid = a.authorid
                  WHERE b.bookid = :bookid AND b.archived = 0"; // Ensure book is not archived

        $stmt = $conn->prepare($query);
        $stmt->bindParam(':bookid', $bookid, PDO::PARAM_INT);
        $stmt->execute();
        $book = $stmt->fetch(PDO::FETCH_ASSOC);

        // Check if the book exists
        if (!$book) {
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json')
                            ->getBody()->write(json_encode(["status" => "error", "message" => "Book not found or has been archived."]));
        }

        // Generate a new token for the user
        $jwt = $request->getAttribute('jwt');
        $username = $jwt->data->username;
        $newToken = createJWT($username, $key);

        // Set the new token in the httpOnly cookie
        $cookie = 'auth_token=' . $newToken . '; Path=/; HttpOnly; SameSite=Strict;';

        // Return the book details and the new token
        $response->getBody()->write(json_encode($book));
        return $response->withHeader('Set-Cookie', $cookie)
                        ->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    }
})->add($jwtMiddleware);



$app->post('/user/logout', function (Request $request, Response $response, array $args) {

    $cookie = 'auth_token=; Path=/; HttpOnly; SameSite=Strict; expires=Thu, 01 Jan 1970 00:00:00 GMT';

    $response->getBody()->write(json_encode(["status" => "success", "message" => "Logged out successfully"]));
    return $response->withHeader('Set-Cookie', $cookie)->withHeader('Content-Type', 'application/json');
});




///This is for the Authors' Side

// Author Registration (no token required)
$app->post('/author/register', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname, $key;
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;
    $name = $data->name;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $checkQuery = "SELECT * FROM authors WHERE username = :username";
        $checkStmt = $conn->prepare($checkQuery);
        $checkStmt->execute(['username' => $uname]);

        if ($checkStmt->rowCount() > 0) {
            $response->getBody()->write(json_encode(["status" => "error", "message" => "Username already taken"]));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $sql = "INSERT INTO authors (name, username, password) VALUES (:name, :username, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['name' => $name, 'username' => $uname, 'password' => hash('SHA256', $pass)]);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Author registration successful"]));
        return $response->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    }
});

// Author Login (no token required)
$app->post('/author/login', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname, $key;
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $sql = "SELECT * FROM authors WHERE username = :username AND password = :password";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['username' => $uname, 'password' => hash('SHA256', $pass)]);
        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($data) {
            $token = createJWT($uname, $key);
            $cookie = 'auth_token=' . $token . '; Path=/; HttpOnly; SameSite=Strict;';
            $response->getBody()->write(json_encode(["status" => "success", "message" => "Login successful"]));
            return $response->withHeader('Set-Cookie', $cookie)->withHeader('Content-Type', 'application/json');
        } else {
            $response->getBody()->write(json_encode(["status" => "failed", "message" => "Authentication failed"]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "failed", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    }
});

// Author adding a book (JWT token required)
$app->post('/author/books/add', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname, $key;

    $data = json_decode($request->getBody());
    $title = $data->title;
    $content = $data->content;

    // Get the author username from JWT token
    $jwt = $request->getAttribute('jwt');
    $authorUsername = $jwt->data->username;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch the authorid using the username from the JWT token
        $authorQuery = "SELECT authorid FROM authors WHERE username = :username";
        $authorStmt = $conn->prepare($authorQuery);
        $authorStmt->execute(['username' => $authorUsername]);
        $author = $authorStmt->fetch(PDO::FETCH_ASSOC);

        if (!$author) {
            $response->getBody()->write(json_encode(["status" => "error", "message" => "Author not found"]));
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }

        $authorid = $author['authorid'];

        // Insert the new book with the correct authorid
        $sql = "INSERT INTO books (authorid, title, content) VALUES (:authorid, :title, :content)";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['authorid' => $authorid, 'title' => $title, 'content' => $content]);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Book added successfully"]));
        return $response->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    }
})->add($jwtMiddleware);


// Author updating a book (JWT token required)
$app->put('/author/books/edit/{bookid}', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname, $key;

    $bookid = $args['bookid'];
    $data = json_decode($request->getBody());
    $title = $data->title;
    $content = $data->content;

    $jwt = $request->getAttribute('jwt');
    $authorUsername = $jwt->data->username;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch the authorid using the username from the JWT token
        $authorQuery = "SELECT authorid FROM authors WHERE username = :username";
        $authorStmt = $conn->prepare($authorQuery);
        $authorStmt->execute(['username' => $authorUsername]);
        $author = $authorStmt->fetch(PDO::FETCH_ASSOC);

        if (!$author) {
            $response->getBody()->write(json_encode(["status" => "error", "message" => "Author not found"]));
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }

        $authorid = $author['authorid'];

        // Ensure the book belongs to the logged-in author
        $bookQuery = "SELECT * FROM books WHERE bookid = :bookid AND authorid = :authorid";
        $bookStmt = $conn->prepare($bookQuery);
        $bookStmt->execute(['bookid' => $bookid, 'authorid' => $authorid]);
        $book = $bookStmt->fetch(PDO::FETCH_ASSOC);

        if (!$book) {
            $response->getBody()->write(json_encode(["status" => "error", "message" => "Book not found or you do not have permission to edit this book"]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Update the book's title and content
        $updateQuery = "UPDATE books SET title = :title, content = :content WHERE bookid = :bookid AND authorid = :authorid";
        $updateStmt = $conn->prepare($updateQuery);
        $updateStmt->execute(['title' => $title, 'content' => $content, 'bookid' => $bookid, 'authorid' => $authorid]);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Book updated successfully"]));
        return $response->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    }
})->add($jwtMiddleware);


// Author deleting a book (JWT token required)
$app->delete('/author/books/delete/{bookid}', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname, $key;

    $bookid = $args['bookid'];

    // Get the author username from JWT token
    $jwt = $request->getAttribute('jwt');
    $authorUsername = $jwt->data->username;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch the authorid using the username from the JWT token
        $authorQuery = "SELECT authorid FROM authors WHERE username = :username";
        $authorStmt = $conn->prepare($authorQuery);
        $authorStmt->execute(['username' => $authorUsername]);
        $author = $authorStmt->fetch(PDO::FETCH_ASSOC);

        if (!$author) {
            $response->getBody()->write(json_encode(["status" => "error", "message" => "Author not found"]));
            return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
        }

        $authorid = $author['authorid'];

        // Check if the book belongs to the logged-in author
        $bookQuery = "SELECT * FROM books WHERE bookid = :bookid AND authorid = :authorid";
        $bookStmt = $conn->prepare($bookQuery);
        $bookStmt->execute(['bookid' => $bookid, 'authorid' => $authorid]);
        $book = $bookStmt->fetch(PDO::FETCH_ASSOC);

        if (!$book) {
            $response->getBody()->write(json_encode(["status" => "error", "message" => "Book not found or you do not have permission to delete this book"]));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        // Delete the book
        $deleteQuery = "DELETE FROM books WHERE bookid = :bookid AND authorid = :authorid";
        $deleteStmt = $conn->prepare($deleteQuery);
        $deleteStmt->execute(['bookid' => $bookid, 'authorid' => $authorid]);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Book deleted successfully"]));
        return $response->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    }
})->add($jwtMiddleware);


// Author logout (JWT token required)
$app->post('/author/logout', function (Request $request, Response $response, array $args) {
    // Clear the auth_token cookie
    $cookie = 'auth_token=; Path=/; HttpOnly; SameSite=Strict; expires=Thu, 01 Jan 1970 00:00:00 GMT';

    $response->getBody()->write(json_encode(["status" => "success", "message" => "Logged out successfully"]));
    return $response->withHeader('Set-Cookie', $cookie)->withHeader('Content-Type', 'application/json');
});







// Middleware to check JWT token stored in httpOnly cookies for Admin
$adminJwtMiddleware = function (Request $request, Response $response, $next) {
    $cookies = $request->getCookieParams();
    $token = $cookies['admin_auth_token'] ?? '';

    if ($token) {
        try {
            $decoded = JWT::decode($token, new Key($GLOBALS['key'], 'HS256'));
            $request = $request->withAttribute('jwt', $decoded);

            // Proceed with the request
            $response = $next($request, $response);

            // After the action, generate a new token and set the cookie
            $username = $decoded->data->username;
            $newToken = createJWT($username, $GLOBALS['key']); // Same helper function
            $cookie = 'admin_auth_token=' . $newToken . '; Path=/; HttpOnly; SameSite=Strict;';

            return $response->withHeader('Set-Cookie', $cookie);
        } catch (Exception $e) {
            $response->getBody()->write(json_encode(["status" => "failed", "message" => "Unauthorized: " . $e->getMessage()]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }
    } else {
        $response->getBody()->write(json_encode(["status" => "failed", "message" => "Token not provided"]));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }
};


$app->post('/admin/register', function ($request, $response) use ($pdo) {
    // Predefined username and password
    $predefinedUsername = 'adminls';
    $predefinedPassword = 'cit@adminls';

    // Check if admin already exists in the database
    $stmt = $pdo->prepare("SELECT * FROM admin WHERE username = :username");
    $stmt->execute(['username' => $predefinedUsername]);
    $admin = $stmt->fetch();

    if ($admin) {
        // If an admin already exists, deny registration
        return $response->withJson(['message' => 'Admin already registered.'], 403);
    }

    // Hash the predefined password for storage
    $hashedPassword = password_hash($predefinedPassword, PASSWORD_DEFAULT);

    // Insert admin into the database
    $stmt = $pdo->prepare("INSERT INTO admin (username, password) VALUES (:username, :password)");
    $stmt->execute([
        'username' => $predefinedUsername,
        'password' => $hashedPassword
    ]);

    return $response->withJson(['message' => 'Admin registered successfully.']);
});



// Admin Login (no token required)
$app->post('/admin/login', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname, $key;
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;

    // Check credentials (this should be done securely)
    if ($uname === 'adminls' && $pass === 'cit@adminls') {
        // Create JWT token for admin
        $token = createJWT($uname, $key);
        
        // Store the token in httpOnly cookie
        $cookie = 'admin_auth_token=' . $token . '; Path=/; HttpOnly; SameSite=Strict;';
        $response->getBody()->write(json_encode(["status" => "success", "message" => "Admin login successful"]));
        return $response->withHeader('Set-Cookie', $cookie)->withHeader('Content-Type', 'application/json');
    } else {
        $response->getBody()->write(json_encode(["status" => "failed", "message" => "Authentication failed"]));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }
});

$app->post('/admin/logout', function (Request $request, Response $response, array $args) {
    $cookie = 'admin_auth_token=; Path=/; HttpOnly; SameSite=Strict; expires=Thu, 01 Jan 1970 00:00:00 GMT';
    $response->getBody()->write(json_encode(["status" => "success", "message" => "Logged out successfully"]));
    return $response->withHeader('Set-Cookie', $cookie)->withHeader('Content-Type', 'application/json');
});



//Disabling/enabling a User Account
$app->put('/admin/users/toggle/{userid}', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname;
    $userid = $args['userid'];
    
    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Fetch the current status
        $stmt = $conn->prepare("SELECT status FROM users WHERE userid = :userid");
        $stmt->bindParam(':userid', $userid);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Determine new status
        $newStatus = ($user['status'] === 'enabled') ? 'disabled' : 'enabled';
        
        // Update the user status
        $sql = "UPDATE users SET status = :status WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['status' => $newStatus, 'userid' => $userid]);

        $response->getBody()->write(json_encode(["status" => "success", "message" => "User status updated"]));
        return $response->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    }
})->add($adminJwtMiddleware);


//Archiving / Unarchiving Books
$app->put('/admin/books/toggleArchive/{bookid}', function (Request $request, Response $response, array $args) {
    global $servername, $username, $password, $dbname;
    $bookid = $args['bookid'];
    $data = json_decode($request->getBody());
    $archiveStatus = $data->archive; // true for archive, false for unarchive

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE books SET archived = :archiveStatus WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['archiveStatus' => $archiveStatus, 'bookid' => $bookid]);

        // Generate a new token for the admin after CRUD action
        $jwt = $request->getAttribute('jwt');
        $username = $jwt->data->username;
        $newToken = createJWT($username, $GLOBALS['key']);
        $cookie = 'admin_auth_token=' . $newToken . '; Path=/; HttpOnly; SameSite=Strict;';

        $response->getBody()->write(json_encode(["status" => "success", "message" => "Book archive status updated"]));
        return $response->withHeader('Set-Cookie', $cookie)->withHeader('Content-Type', 'application/json');
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "error", "message" => $e->getMessage()])); 
        return $response->withHeader('Content-Type', 'application/json');
    }
})->add($adminJwtMiddleware);


$app->run();

