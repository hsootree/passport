require('dotenv').config()

const path = require('path')
const express = require('express')
const bodyParser = require('body-parser')
const cookieSession = require('cookie-session')
const bcrypt = require('bcrypt')
const csurf = require('csurf')
const flash = require('connect-flash')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')
const util = require('./util')
const query = require('./query')
const mw = require('./middleware')

const PORT = process.env.PORT || 3000

const app = express()

app.set('view engine', 'pug')
app.set('trust proxy')

app.use(express.static(path.join(__dirname, '..', 'public')))
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieSession({
  name: 'wpsess',
  keys: [
    process.env.SECRET
  ]
}))
app.use(urlencodeMiddleware)
app.use(csrfMiddleware)
app.use(flash())
app.set('view engine', 'pug')

// passport 관련 미들웨어 삽입
app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser((user, done) => {
    // user 객체로부터 세션에 저장할 수 있는 문자열을 만들어서 반환
    done(null, user.id)
    done
  })
  // passport가 유저 정보를 세션에 저장할 수 있도록 직렬화
passport.deserializeUser((id, done) => {
  query.getUserById(id)
    .then(user => {
      if (user) {
        done(null, jser)
      } else {
        done(new Error('아이디가 일치하는 사용자가 없습니다.'))
      }
    })
})

passport.use(new LocalStrategy((username, password, done) => {
  // 인증정보와 일치하는 사용자가 있는지 확인
  query.getUserById(username)
    .then(matched => {
      if (matched && bcrypt.compareSync(password, matched.password)) {
        done(null, matched)
      } else {
        done(new Error('사용자가 이름 혹은 비밀번호가 일치하지 않습니다.')) // 보안상의 문제로 해킹을 할 때 경우의 수를 줄이는 것을 방지하기 위해서 둘중 하나가 틀린 것으로 알려줌. 보안과 접근성의 딜레마..
      }
    })
}))

function authMiddleware(req, res, next) {
  if (req.user) {
    // 로그인이 된 상태이므로 그냥 통과시킨다.
    next()
  } else {
    res.redirect('/login')
  }
}

// passport가 세션으로부터 유저 객체를 가져올 수 있도록 역직렬화
passport.deserializeUser((id, done) => {
  query.getUserById(id)
    .then(user => {
      if (user) {
        done(null, user) // req.user에 저장됨
      } else {
        done(new Error('해당 아이디를 가진 사용자가 없습니다.'))
      }
    })
})

// passport가 아이디와 암호 기반 인증을 수행하도록 strategy 등록
passport.use(new LocalStrategy((username, password, done) => {
  query.compareUser(username, password)
    .then(user => {
      // 인증 성공
      done(null, user)
    })
    .catch(err => {
      if (err instanceof query.LoginError) {
        // 인증 실패: 사용자 책임
        done(null, false, { message: err.message })
      } else {
        // 인증 실패: 서버 책임
        done(err)
      }
    })
}))

app.get('/', mw.loginRequired, (req, res) => {
  res.render('index.pug', req.user)
})

app.get('/login', (req, res) => {
  res.render('login.pug', { errors: req.flash('error'), csrfToken: req.csrfToken() })
})

// passport-local을 통해 생성한 라우트 핸들러
app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}))

app.get('/register', (req, res) => {
  res.render('register.pug')
})

app.post('/register', (req, res, next) => {
  query.createUser(req.body.username, req.body.password)
    .then(user => {
      // passport가 제공하는 `req.login` 메소드
      req.login(user, err => {
        if (err) {
          next(err)
        } else {
          res.redirect('/')
        }
      })
    })
    .catch(util.flashError(req, res))
})

app.post('/logout', (req, res) => {
  // passport가 제공하는 `req.logout` 메소드
  req.logout()
  res.redirect('/login')
})

app.listen(PORT, () => {
  console.log(`listening ${PORT}...`)
})