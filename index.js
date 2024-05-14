const express = require('express');
const session = require('express-session');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');

const app = express();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix);
  }
});

const upload = multer({ storage: storage });

app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
}));

const connection = mysql.createConnection({
  host: '127.0.0.1',
  port: '3306',
  user: 'root',
  password: '12345678',
  database: 'unityhub2'
});

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err.message);
    process.exit(1);
  }
  console.log('Connected to the database!');
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = 'SELECT * FROM users WHERE username = ?';
  connection.query(sql, [username], (err, results) => {
    if (err) {
      console.error('Error querying database:', err.message);
      return res.status(500).json({ error: 'An error occurred while processing your request' });
    }
    if (results.length === 0) {
      // No user found with the provided username
      return res.redirect('/?error=Invalid username or password');
    }

    const user = results[0];
    bcrypt.compare(password, user.password, (bcryptErr, bcryptResult) => {
      if (bcryptErr) {
        console.error('Error comparing passwords:', bcryptErr.message);
        return res.status(500).json({ error: 'An error occurred while processing your request' });
      }
      if (!bcryptResult) {
        // Passwords do not match
        return res.redirect('/?error=Invalid username or password');
      }

      // Passwords match, set user session and redirect to home
      req.session.user = {
        id: user.id,
        username: user.username,
        email: user.email
      };
      res.redirect('/home');
    });
  });
});


const shuffleArray = (array) => {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
};

app.get('/home', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  const user = req.session.user;
  const sql = `
    SELECT posts.*, users.username AS username, users.profile_picture AS profile_picture,
           COUNT(post_comments.post_id) AS comment_count
    FROM posts
    INNER JOIN users ON posts.user_id = users.id
    LEFT JOIN post_comments ON posts.id = post_comments.post_id
    WHERE posts.user_id = ? OR EXISTS (
      SELECT 1 FROM friends WHERE friends.user_id = ? AND friends.friend_id = posts.user_id
    )
    GROUP BY posts.id
    ORDER BY posts.created_at DESC
  `;
  connection.query(sql, [user.id, user.id], (err, posts) => {
    if (err) {
      console.error('Error querying posts from database:', err.message);
      return res.status(500).json({ error: 'An error occurred while processing your request' });
    }
    const friendSql = 'SELECT users.username AS username FROM friends INNER JOIN users ON friends.friend_id = users.id WHERE friends.user_id = ?';
    connection.query(friendSql, [user.id], (friendErr, friends) => {
      if (friendErr) {
        console.error('Error querying friends from database:', friendErr.message);
        return res.status(500).json({ error: 'An error occurred while processing your request' });
      }
      // Shuffle the posts array before rendering
      const shuffledPosts = shuffleArray(posts);
      res.render('home', { posts: shuffledPosts, user, friends });
    });
  });
});


app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.post('/signup', (req, res) => {
  const { username, email, password } = req.body;
  bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
    if (hashErr) {
      console.error('Error hashing password:', hashErr.message);
      return res.status(500).json({ error: 'An error occurred while processing your request' });
    }
    const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    connection.query(sql, [username, email, hashedPassword], (insertErr, result) => {
      if (insertErr) {
        console.error('Error inserting user into database:', insertErr.message);
        return res.status(500).json({ error: 'An error occurred while processing your request' });
      }
      res.sendFile(path.join(__dirname, 'public', 'login.html'));
    });
  });
});

app.post('/like', (req, res) => {
  const { postId, userId } = req.body;
  const checkLikedSql = 'SELECT * FROM post_likes WHERE post_id = ? AND user_id = ?';
  connection.query(checkLikedSql, [postId, userId], (checkLikedErr, likedRows) => {
    if (checkLikedErr) {
      console.error('Error checking if post is already liked:', checkLikedErr.message);
      return res.status(500).json({ error: 'An error occurred while processing your request' });
    }
    if (likedRows.length > 0) {
      const deleteLikeSql = 'DELETE FROM post_likes WHERE post_id = ? AND user_id = ?';
      connection.query(deleteLikeSql, [postId, userId], (deleteLikeErr, deleteResult) => {
        if (deleteLikeErr) {
          console.error('Error deleting like from database:', deleteLikeErr.message);
          return res.status(500).json({ error: 'An error occurred while processing your request' });
        }
        const updateLikesSql = 'UPDATE posts SET likes = likes - 1 WHERE id = ?';
        connection.query(updateLikesSql, [postId], (updateLikesErr, updateResult) => {
          if (updateLikesErr) {
            console.error('Error updating post likes:', updateLikesErr.message);
            return res.status(500).json({ error: 'An error occurred while processing your request' });
          }
          res.json({ message: 'Post unliked successfully', liked: false, likeCount: updateResult.affectedRows });
        });
      });
    } else {
      const insertLikeSql = 'INSERT INTO post_likes (post_id, user_id) VALUES (?, ?)';
      connection.query(insertLikeSql, [postId, userId], (insertLikeErr, result) => {
        if (insertLikeErr) {
          console.error('Error inserting like into database:', insertLikeErr.message);
          return res.status(500).json({ error: 'An error occurred while processing your request' });
        }
        const updateLikesSql = 'UPDATE posts SET likes = likes + 1 WHERE id = ?';
        connection.query(updateLikesSql, [postId], (updateLikesErr, updateResult) => {
          if (updateLikesErr) {
            console.error('Error updating post likes:', updateLikesErr.message);
            return res.status(500).json({ error: 'An error occurred while processing your request' });
          }
          res.json({ message: 'Post liked successfully', liked: true, likeCount: updateResult.affectedRows });
        });
      });
    }
  });
});


app.get('/check-like', (req, res) => {
  const { postId, userId } = req.query;
  const checkLikedSql = 'SELECT * FROM post_likes WHERE post_id = ? AND user_id = ?';
  connection.query(checkLikedSql, [postId, userId], (checkLikedErr, likedRows) => {
      if (checkLikedErr) {
          console.error('Error checking if post is already liked:', checkLikedErr.message);
          return res.status(500).json({ error: 'An error occurred while processing your request' });
      }
      res.json({ liked: likedRows.length > 0 });
  });
});

app.get('/posts', (req, res) => {
  const userId = req.session.user.id;
  const sql = `
      SELECT posts.*, users.username AS username, users.profile_picture AS profile_picture
      FROM posts
      INNER JOIN users ON posts.user_id = users.id
      WHERE posts.user_id != ?
      ORDER BY posts.created_at DESC
  `;
  connection.query(sql, [userId], (err, results) => {
      if (err) {
          console.error('Error querying posts from database:', err.message);
          return res.status(500).json({ error: 'An error occurred while processing your request' });
      }
      res.json(results);
  });
});

app.post('/post', upload.single('file'), (req, res) => {
  const { userId, text } = req.body;
  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }
  const sql = 'INSERT INTO posts (user_id, text) VALUES (?, ?)';
  connection.query(sql, [userId, text], (err, result) => {
    if (err) {
      console.error('Error inserting post into database:', err.message);
      return res.status(500).json({ error: 'An error occurred while processing your request' });
    }
    const postId = result.insertId;
    const getPostSql = `
      SELECT posts.*, users.username AS username, users.profile_picture AS profile_picture
      FROM posts
      INNER JOIN users ON posts.user_id = users.id
      WHERE posts.id = ?
    `;
    connection.query(getPostSql, [postId], (getPostErr, postResult) => {
      if (getPostErr || postResult.length === 0) {
        console.error('Error retrieving newly added post:', getPostErr ? getPostErr.message : 'Post not found');
        return res.status(500).json({ error: 'An error occurred while processing your request' });
      }
      res.status(200).json(postResult[0]);
    });
  });
});
 
//  route to handle posting comments
app.post('/comment', (req, res) => {
  const { postId, commentText } = req.body;
  const userId = req.session.user.id;

  const sql = 'INSERT INTO post_comments (post_id, user_id, text) VALUES (?, ?, ?)';
  connection.query(sql, [postId, userId, commentText], (err, result) => {
      if (err) {
          console.error('Error inserting comment into database:', err.message);
          return res.status(500).json({ error: 'An error occurred while processing your request' });
      }

      // Retrieve the newly added comment from the database
      const getCommentSql = `
          SELECT pc.*, u.username
          FROM post_comments pc
          INNER JOIN users u ON pc.user_id = u.id
          WHERE pc.id = ?
      `;
      connection.query(getCommentSql, [result.insertId], (getCommentErr, commentResult) => {
          if (getCommentErr || commentResult.length === 0) {
              console.error('Error retrieving newly added comment:', getCommentErr ? getCommentErr.message : 'Comment not found');
              return res.status(500).json({ error: 'An error occurred while processing your request' });
          }
          const newComment = commentResult[0];
          res.status(200).json({ message: 'Comment added successfully', comment: newComment });

      });
  });
});

app.get('/comments', (req, res) => {
  const postId = req.query.postId;
  const sql = `
      SELECT post_comments.*, users.username
      FROM post_comments
      INNER JOIN users ON post_comments.user_id = users.id
      WHERE post_comments.post_id = ?
  `;
  connection.query(sql, [postId], (err, comments) => {
      if (err) {
          console.error('Error fetching comments:', err.message);
          return res.status(500).json({ error: 'An error occurred while processing your request' });
      }
      res.json(comments);
  });
});

// Serve the add friends.html page
app.get('/addfriend', (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    // If user is not logged in, redirect to the login page
    return res.redirect('/');
  }
  
  // If user is logged in, serve the add friends.html page
  res.sendFile(path.join(__dirname, 'public', 'addfriend.html'));
});


app.get('/search-users', (req, res) => {
  const searchQuery = req.query.q;
  const sql = 'SELECT id, username, email FROM users WHERE username LIKE ? OR email LIKE ?';
  connection.query(sql, [`%${searchQuery}%`, `%${searchQuery}%`], (err, users) => {
      if (err) {
          console.error('Error searching users:', err.message);
          return res.status(500).json({ error: 'An error occurred while processing your request' });
      }
      res.json(users);
  });
});

app.post('/add-friend/:friendId', (req, res) => {
  // Extract the user ID from the session
  const userId = req.session.user.id;
  // Extract the friend ID from the request parameters
  const friendId = req.params.friendId;

  // Check if the friendId is valid (exists in the database)
  const checkFriendQuery = 'SELECT * FROM users WHERE id = ?';
  connection.query(checkFriendQuery, [friendId], (err, results) => {
    if (err) {
      console.error('Error checking friend ID:', err.message);
      return res.status(500).send('Internal Server Error');
    }
    if (results.length === 0) {
      // Friend ID not found in the database
      return res.status(404).send('Friend not found');
    }

    // Check if the friendship already exists
    const checkFriendshipQuery = 'SELECT * FROM friends WHERE user_id = ? AND friend_id = ?';
    connection.query(checkFriendshipQuery, [userId, friendId], (friendshipErr, friendshipResults) => {
      if (friendshipErr) {
        console.error('Error checking friendship:', friendshipErr.message);
        return res.status(500).send('Internal Server Error');
      }
      if (friendshipResults.length > 0) {
        // Friendship already exists
        return res.status(400).send('Friendship already exists');
      }

      // Insert a new friendship into the database
      const insertFriendshipQuery = 'INSERT INTO friends (user_id, friend_id) VALUES (?, ?)';
      connection.query(insertFriendshipQuery, [userId, friendId], (insertErr, insertResults) => {
        if (insertErr) {
          console.error('Error inserting friendship:', insertErr.message);
          return res.status(500).send('Internal Server Error');
        }
        // Friendship added successfully
        return res.status(200).send('Friend added successfully');
      });
    });
  });
});

// POST '/add-friend' route to handle adding friends functionality
app.post('/add-friend', (req, res) => {
  const { userId, friendId } = req.body;

  // Check if the friendId is valid (exists in the database)
  db.query('SELECT * FROM users WHERE id = ?', [friendId], (err, results) => {
      if (err) {
          console.error(err);
          return res.status(500).send("Internal Server Error");
      }

      if (results.length === 0) {
          // Friend ID not found in the database
          return res.status(404).send("Friend not found");
      }

      // Insert a new friend relationship into the database
      db.query('INSERT INTO friends (user_id, friend_id) VALUES (?, ?)', [userId, friendId], (err, results) => {
          if (err) {
              console.error(err);
              return res.status(500).send("Internal Server Error");
          }

          // Friend added successfully
          return res.status(200).send("Friend added successfully");
      });
  });
});
app.get('/chat', (req, res) => {
  // Check if the user is logged in
  if (!req.session.user) {
    // If the user is not logged in, redirect to the login page
    return res.redirect('/');
  }

  // If the user is logged in, serve the chat.html page
  res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

app.post('/send-message', (req, res) => {
  const { friendId, message } = req.body;
  const userId = req.session.user.id;

  const sql = 'INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)';
  connection.query(sql, [userId, friendId, message], (err, result) => {
    if (err) {
      console.error('Error inserting message into database:', err.message);
      return res.status(500).json({ error: 'An error occurred while processing your request' });
    }
    res.status(200).json({ message: 'Message sent successfully' });
  });
});

// Route to fetch messages between the current user and a friend
app.get('/messages', (req, res) => {
  const friendId = req.query.friendId;
  const userId = req.session.user.id;

  const sql = `
    SELECT sender_id, receiver_id, message
    FROM chat_messages
    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
    ORDER BY sent_at ASC
  `;
  connection.query(sql, [userId, friendId, friendId, userId], (err, messages) => {
    if (err) {
      console.error('Error fetching messages:', err.message);
      return res.status(500).json({ error: 'An error occurred while processing your request' });
    }
    res.json(messages.map(message => ({
      ...message,
      isSender: message.sender_id === userId
    })));
  });
});

// Route to fetch friends of the current user

app.get('/friends', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const userId = req.session.user.id;
  const sql = 'SELECT users.id, users.username, users.profile_picture FROM users INNER JOIN friends ON users.id = friends.friend_id WHERE friends.user_id = ?';
  connection.query(sql, [userId], (err, friends) => {
    if (err) {
      console.error('Error fetching friends:', err.message);
      return res.status(500).json({ error: 'An error occurred while fetching friends' });
    }
    res.json(friends);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
