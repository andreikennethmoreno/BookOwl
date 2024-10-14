import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import axios from "axios";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from 'cookie-parser';
import env from "dotenv";
import passport from "passport";
import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = 3000;
const saltRounds = 10;
const  JWT_SECRET_KEY = "HelloWorld";

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
env.config();

const GOOGLE_BOOKS_API_KEY = process.env.GOOGLE_BOOKS_API_KEY;

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();



app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE gmail = $1", [
      email,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      //verifying the password
      bcrypt.compare(loginPassword, storedHashedPassword, (err, isMatch) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return res.status(500).send("Internal Server Error");
        }
        if (isMatch) {
          // Create JWT token
          const token = jwt.sign(
            { id: user.id, email: user.gmail }, // Make sure to include the id and email in the payload
            JWT_SECRET_KEY,
            { expiresIn: "1h" }
          );
      
          // Set token in cookie
          res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',  // Use HTTPS in production
            maxAge: 3600000  // 1 hour
          });
        
      
          res.redirect('/myBooks');
        } else {
          res.status(401).send("Incorrect Password");
        }
      });
      
      
    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.log(err);
  }
});

const authenticateJWT = (req, res, next) => {
  const token = req.cookies.token;

  if (token) {
    jwt.verify(token, JWT_SECRET_KEY, (err, user) => {
      if (err) {
        return res.sendStatus(403); // Invalid token
      }
      console.log('Decoded user:', user); // Log decoded token
      req.user = user; // Store user info in request
      next();
    });
  } else {
    res.redirect("/login");
  }
};


app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE gmail = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //bcrypt hash 
      bcrypt.hash(password, saltRounds, async(err, hash) => {
        if (err) {
          console.log(err);
        } else{
          const result = await db.query(
            "INSERT INTO users (gmail, password) VALUES ($1, $2)",
            [email, hash]
          );
          console.log(result);
          res.redirect('/myBooks');

        }
     
      });

      
    }
  } catch (err) {
    console.log(err);
  }
});


// Google OAuth callback route
app.get("/auth/google/myBooks",
  passport.authenticate("google", { failureRedirect: "/login", session: false }),
  (req, res) => {
    // Successful authentication, generate JWT
    const user = req.user;  // Assuming `req.user` is set after successful login
    
    // Generate a JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET_KEY, { expiresIn: '1h' });

    // Set the JWT in an HTTP-only cookie
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

    // Redirect to /mybooks
    res.redirect("/myBooks");
  }
);
passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET, 
  callbackURL: "http://localhost:3000/auth/google/myBooks", 
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
}, async (accessToken, refreshToken, profile, cb) => {
  console.log(profile);

  try {
    const result = await db.query("SELECT * FROM users WHERE gmail = $1", [profile.emails[0].value]);
    
    let user;
    if (result.rows.length === 0) {
      const newUser = await db.query("INSERT INTO users (gmail, password) VALUES ($1, $2) RETURNING *", [profile.emails[0].value, "google"]);
      user = newUser.rows[0];
    } else {
      user = result.rows[0];
      console.log("login success");
    }

    // Pass the user object to the next middleware
    cb(null, user);

  } catch (err) {
    cb(err);
  }
}));



passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});


app.get("/auth/google", passport.authenticate("google", {
  scope:  ["profile", "email"],
  })
);

app.get("/login", (req, res) => {
  res.render("login.ejs", { user: res.locals.user });
});

app.get("/register", (req, res) => {
  res.render("register.ejs", { user: res.locals.user });
});

app.post("/logout", authenticateJWT, (req, res) => {
  res.clearCookie("token"); // Clear the JWT cookie
  res.redirect("/login"); // Redirect to the login page
});


app.get("/", authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  console.log("this is the user" + userId)

  try {
    res.render("searchBooks.ejs", {user: req.user, searchTerm: "" });
  } catch (error) {
    console.error(error);
    res.status(500).send("An error occurred while fetching data.");
  }
});



app.post("/searchBooks",authenticateJWT, async (req, res) => {
  const searchBook = req.body.searchBook;
  const userId = req.user.id; // Get the user ID from the JWT token

  console.log(searchBook);
  try {
    // Fetch data from Google Books API
    const response = await axios.get(`https://www.googleapis.com/books/v1/volumes?q=${searchBook}&key=${GOOGLE_BOOKS_API_KEY}`);
    const result = response.data.items; // Google Books API returns an 'items' array
    console.log(result);

    // Map the response to structure it according to what your frontend expects
    const formattedResult = result.map(item => ({
      id: item.id,
      title: item.volumeInfo.title || 'No Title',
      authors: item.volumeInfo.authors || ['Unknown'], // Google Books gives authors as an array
      cover: item.id ? `https://books.google.com/books/content?id=${item.id}&printsec=frontcover&img=1&zoom=3&source=gbs_api` : 'default_cover_image_url'
    }));


    // Render the searchBooks page with formatted data
    res.render("searchBooks.ejs", { data: formattedResult, searchTerm: searchBook, user: req.user });
  } catch (error) {
    console.error("Failed to make request:", error.message);
    res.render("errorPage.ejs", {
      error: error.message,
    });
  }
});


app.post("/addBook", authenticateJWT, async (req, res) => {
  let { title, url, author } = req.body;
  const formattedDate = new Date();
  const dateAdded = formattedDate.toDateString();
  const userId = req.user.id;
  let status = "Reading";

  console.log("this is the userID in addBook: " + userId);
  console.log(req.body);

  console.log(userId + "is the user id")

  let bookId = 0; // Declare bookId here
  try {
    // First, check if the book already exists
    const result = await db.query(
      "SELECT id FROM mybooks WHERE booktitle = $1 AND bookauthor = $2",
      [title, author]
    );

    if (result.rows.length > 0) {
      // Book exists, log the existing ID
      console.log('Existing book ID:', result.rows[0].id);
      bookId = result.rows[0].id; // Set bookId to the existing book's ID
    } else {
      // Book does not exist, insert the new book
      const insertResult = await db.query(
        "INSERT INTO mybooks (booktitle, bookcoverurl, bookauthor, dateadded) VALUES ($1, $2, $3, $4) RETURNING id",
        [title, url, author, dateAdded]
      );
      console.log('Inserted book ID:', insertResult.rows[0].id); // Log the ID of the newly inserted book
      bookId = insertResult.rows[0].id; // Set bookId to the newly inserted book's ID
    }

    // Insert into usersbooks regardless of whether the book was newly inserted or already existed
    await db.query(
      "INSERT INTO usersbooks (book_id, user_id, status) VALUES ($1, $2, $3)",
      [bookId, userId, status]  // Use bookId instead of hardcoded values
    );
    console.log('Inserted into usersbooks:', { bookId, userId, status });

    // Redirect after processing both cases
    res.redirect('/myBooks');
    console.log('Success');

  } catch (error) {
    console.error("Failed to make request:", error.message);
    res.status(500).send("An error occurred while adding the book.");
  }
});



app.get("/myBooks", authenticateJWT, async (req, res) => {
  const userId = req.user.id; // Get the user ID from the JWT token

  console.log("contents : " + req.body)
  try {
    // Step 1: Get all book_ids for the user from usersbooks
    const userBooksResult = await db.query(
      "SELECT book_id FROM usersbooks WHERE user_id = $1",
      [userId]
    );

    const bookIds = userBooksResult.rows.map(row => row.book_id); // Extract the book_id values

    // Step 2: If there are no books, return an empty list
    if (bookIds.length === 0) {
      return res.render("myBooks.ejs", {
        listBooks: [], 
        user: req.user
      });
    }

    const booksResult = await db.query(`
      SELECT mb.*, ub.rating
      FROM mybooks mb
      JOIN usersbooks ub ON mb.id = ub.book_id
      WHERE ub.user_id = $1 AND mb.id = ANY($2::int[])
    `, [userId, bookIds]);
    const books = booksResult.rows; // Get the list of books

    // Step 4: Render the books in your EJS template
    res.render("myBooks.ejs", {
      listBooks: books,
      user: req.user
    });
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred while fetching books.");
  }
});


app.get("/bookStatus", authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  console.log(req.user);
  console.log("books status user id" + userId);

  try {
    // Query to get completed books with cover URL
    const completedQuery = await db.query(
      `SELECT ub.*, mb.bookcoverurl
       FROM usersbooks ub
       JOIN mybooks mb ON ub.book_id = mb.id
       WHERE ub.user_id = $1 AND ub.status = 'Completed'`,
      [userId]
    );

    // Query to get dropped books with cover URL
    const droppedQuery = await db.query(
      `SELECT ub.*, mb.bookcoverurl
       FROM usersbooks ub
       JOIN mybooks mb ON ub.book_id = mb.id
       WHERE ub.user_id = $1 AND ub.status = 'Dropped'`,
      [userId]
    );

    // Query to get reading books with cover URL
    const readingQuery = await db.query(
      `SELECT ub.*, mb.bookcoverurl
       FROM usersbooks ub
       JOIN mybooks mb ON ub.book_id = mb.id
       WHERE ub.user_id = $1 AND ub.status = 'Reading'`,
      [userId]
    );

    // Query to get on hold books with cover URL
    const onHoldQuery = await db.query(
      `SELECT ub.*, mb.bookcoverurl
       FROM usersbooks ub
       JOIN mybooks mb ON ub.book_id = mb.id
       WHERE ub.user_id = $1 AND ub.status = 'On Hold'`,
      [userId]
    );

    const completedBooks = completedQuery.rows;
    const droppedBooks = droppedQuery.rows;
    const readingBooks = readingQuery.rows;
    const onHoldBooks = onHoldQuery.rows;
    
    res.render("bookStatus.ejs", {
      listCompleted: completedBooks,
      listDropped: droppedBooks,
      listReading: readingBooks,
      listOnHold: onHoldBooks,
      user: req.user
    });
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred while retrieving book statuses.");
  }
});

app.get("/thisBook/:id", authenticateJWT, async (req, res) => {
  const bookId = parseInt(decodeURIComponent(req.params.id), 10);
  const userId = req.user.id; // Assuming `req.user` contains the user info including `id`

  console.log("the book id is " + bookId);
  
  try {
    const result = await db.query(`
      SELECT myBooks.*, usersbooks.*
      FROM myBooks
      JOIN usersbooks ON myBooks.id = usersbooks.book_id
      WHERE myBooks.id = $1 AND usersbooks.user_id = $2
    `, [bookId, userId]); // Include userId in the query parameters

    const thisBook = result.rows[0]; 
    console.log(result);

    if (thisBook) {
      res.render("thisBook.ejs", { thisBook, user: req.user });
    } else {
      res.status(404).send("Book not found for the user");
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Error retrieving the book details");
  }
});




app.post("/deleteThisBook/:id", async (req, res) => {
  const bookId = decodeURIComponent(req.params.id);
  console.log("Deleting book with ID:", bookId);
  try {
    // Delete the book from the database
    const result = await db.query("DELETE FROM usersbooks WHERE book_id = $1 RETURNING *", [bookId]);

    if (result.rowCount === 0) {
      // If no rows were deleted, the book was not found
      res.status(404).send("Book not found");
    } else {
      // Book successfully deleted
      console.log("Deleted book:", result.rows[0]);
      res.redirect("/myBooks"); // Redirect to a page listing books or an appropriate page
    }
  } catch (err) {
    console.error("Error deleting the book:", err);
    res.status(500).send("Error deleting the book");
  }
});

app.post("/editStatus", authenticateJWT, async (req, res) => {
  const editedStatus = req.body.updatedStatusTitle;
  const updatedStatusId = req.body.updatedStatusId;  // This is the book_id
  const userId = req.user.id;  // Assuming you get `user_id` from JWT or request body

  console.log("Updated status: " + editedStatus);
  console.log("Updated book_id: " + updatedStatusId);
  console.log("User ID: " + userId);

  let formattedDate = new Date();
  const dateReviewed = formattedDate.toDateString();
  
  try {
    await db.query(
      "UPDATE usersbooks SET status = $1, datereviewed = $2 WHERE book_id = $3 AND user_id = $4", 
      [editedStatus, dateReviewed, updatedStatusId, userId]
    );
    res.redirect('back');

  } catch (err) {
    console.log(err);
    res.status(500).send('Server error');
  }
});



app.post("/editRating",authenticateJWT, async (req, res) => {
  const updatedRating = req.body.updatedRating;
  const updatedRatingId = req.body.updatedRatingId;

  console.log("Updated rating: " + updatedRating)
  console.log("Updated ratingId: " + updatedRatingId)


  let formattedDate = new Date();
  const dateReviewed = formattedDate.toDateString();
  console.log("rating is" + updatedRating, updatedRatingId)
  try {
    await db.query("UPDATE usersbooks SET rating = $1, datereviewed = $2 WHERE book_id = $3", 
                   [updatedRating, dateReviewed, updatedRatingId]);
    res.redirect('back');
  } catch (err) {
    console.log(err);
    res.status(500).send('Server error');
  }
});


app.post("/editReview",authenticateJWT, async (req, res) => {
  const editedReview = req.body.updatedReviewTitle;
  const updatedReviewId = req.body.updatedReviewId;
  let formattedDate= new Date();
  const dateReviewed = formattedDate.toDateString();
  console.log(editedReview);
  console.log(updatedReviewId);
  try {
    await db.query("UPDATE usersbooks SET datereviewed = $1, review = $2 WHERE book_id = $3", [dateReviewed, editedReview, updatedReviewId]);
    res.redirect('back')
  } catch (err) {
    console.log(err)
  }
});


app.post("/sort", authenticateJWT, async (req, res) => {
  const validCategories = ['booktitle', 'rating', 'dateadded', 'datereviewed', 'bookauthor'];
  const category = validCategories.includes(req.body.category) ? req.body.category : 'booktitle';
  const sortStatus = req.body.sortStatus;

  console.log(`Sorting by category: ${category}`);
  console.log(`Filtering by status: ${sortStatus}`);

  try {
    let result;
    if (sortStatus) {
      // Join usersbooks with mybooks filtering by status and user_id
      result = await db.query(`
        SELECT ub.*, mb.*
        FROM usersbooks ub
        JOIN mybooks mb ON ub.book_id = mb.id
        WHERE ub.status = $1 AND ub.user_id = $2
      `, [sortStatus, req.user.id]);
    } else {
      // Join usersbooks with mybooks and order by the specified category, filtering by user_id
      result = await db.query(`
        SELECT ub.*, mb.*
        FROM usersbooks ub
        JOIN mybooks mb ON ub.book_id = mb.id
        WHERE ub.user_id = $1
        ORDER BY ${category} DESC
      `, [req.user.id]);
    }

    const books = result.rows;
    res.render("myBooks.ejs", {
      listBooks: books,
      status: sortStatus || null, // Send status as null if not filtering
      category: sortStatus ? null : category, // Send category only if not filtering by status
      user: req.user
    });
  } catch (err) {
    console.error('Database query error:', err);
    res.status(500).send('Server error');
  }
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
