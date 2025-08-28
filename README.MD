# 🌱 EcoTrack - Community Sustainability Tracker

A web application that empowers individuals to track their sustainable actions and join a community working towards achieving UN Sustainable Development Goals (SDGs) 11, 12, and 13.

![EcoTrack Banner](https://images.unsplash.com/photo-1441974231531-c6227db76b6e?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1000&q=80)

## 🎯 SDG Alignment

- **SDG 11: Sustainable Cities and Communities** - Promoting sustainable urban living through community engagement
- **SDG 12: Responsible Consumption and Production** - Encouraging responsible consumption patterns
- **SDG 13: Climate Action** - Taking urgent action to combat climate change and its impacts

## ✨ Features

### 🔐 User Management
- **User Registration & Authentication** - Secure account creation and login system
- **User Dashboard** - Personalized dashboard with statistics and progress tracking
- **Profile Management** - Track membership duration and personal impact

### 📊 Action Tracking
- **Log Sustainable Actions** - Easy-to-use form for recording eco-friendly activities
- **Points System** - Earn points for different sustainable actions:
  - 🌳 Plant a Tree: 50 points
  - ♻️ Recycle Items: 10 points
  - 🚌 Use Public Transport: 15 points
  - 🥤 Reduce Plastic Use: 20 points
  - 💡 Energy Saving: 25 points
  - 💧 Water Conservation: 15 points
  - 🚴 Bike/Walk Instead of Driving: 30 points
  - 🍃 Composting: 35 points
  - 🛒 Buy Local Products: 20 points
  - 🔋 Use Renewable Energy: 40 points

### 🏆 Gamification
- **Leaderboard** - Community rankings based on impact points
- **Badge System** - Achievement badges for reaching milestones:
  - 🌟 Eco Starter (100 points)
  - ⚔️ Green Warrior (500 points)
  - 🛡️ Planet Protector (1000 points)
  - 🏆 Sustainability Champion (2000 points)
  - 🌳 Tree Planter (plant 10 trees)
  - ♻️ Recycling Hero (recycle 50 times)

### 📈 Analytics & Visualization
- **Interactive Dashboard** with Chart.js visualizations
- **Category Statistics** - Pie chart showing actions by category
- **Monthly Activity** - Line chart displaying activity trends
- **Community Statistics** - Real-time community impact metrics

## 🛠️ Tech Stack

### Backend
- **Flask** - Python web framework
- **MongoDB** - NoSQL database for storing users and actions
- **PyMongo** - MongoDB driver for Python
- **Werkzeug** - Password hashing and security

### Frontend
- **HTML5/CSS3** - Modern responsive design
- **Bootstrap 5** - UI framework for responsive layouts
- **Chart.js** - Interactive data visualizations
- **Font Awesome** - Icons and visual elements

### Database Schema
```javascript
// Users Collection
{
  _id: ObjectId,
  username: String,
  email: String,
  password: String (hashed),
  joined_date: DateTime,
  total_points: Number
}

// Actions Collection
{
  _id: ObjectId,
  user_id: String,
  action_type: String,
  description: String,
  points: Number,
  timestamp: DateTime
}
```

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- MongoDB (local installation or MongoDB Atlas)
- pip (Python package manager)

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/ecotrack.git
cd ecotrack
```

### 2. Create Virtual Environment
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. MongoDB Setup

#### Option A: Local MongoDB
1. Install MongoDB Community Edition
2. Start MongoDB service:
   ```bash
   # On Windows (if installed as service)
   net start MongoDB
   
   # On macOS
   brew services start mongodb/brew/mongodb-community
   
   # On Linux
   sudo systemctl start mongod
   ```

#### Option B: MongoDB Atlas (Cloud)
1. Create account at [MongoDB Atlas](https://www.mongodb.com/atlas)
2. Create a cluster and get connection string
3. Set environment variable:
   ```bash
   export MONGO_URI="mongodb+srv://username:password@cluster.mongodb.net/ecotrack"
   ```

### 5. Environment Configuration
Create a `.env` file in the project root:
```env
MONGO_URI=mongodb://localhost:27017/
FLASK_SECRET_KEY=your-super-secret-key-change-in-production
FLASK_ENV=development
```

### 6. Run the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## 📁 Project Structure
```
ecotrack/
│
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── README.md              # Project documentation
├── .env                   # Environment variables (create this)
│
└── templates/             # HTML templates
    ├── base.html          # Base template with navigation
    ├── index.html         # Homepage
    ├── register.html      # User registration
    ├── login.html         # User login
    ├── dashboard.html     # User dashboard
    ├── log_action.html    # Log sustainable actions
    └── leaderboard.html   # Community leaderboard
```

## 🔧 Configuration

### Environment Variables
- `MONGO_URI`: MongoDB connection string
- `FLASK_SECRET_KEY`: Secret key for session management
- `FLASK_ENV`: Environment mode (development/production)

### MongoDB Collections
The application automatically creates the following collections:
- `users`: User accounts and profiles
- `actions`: Logged sustainable actions

## 📊 API Endpoints

### Authentication
- `GET /` - Homepage with community statistics
- `GET /register` - User registration form
- `POST /register` - Create new user account
- `GET /login` - User login form
- `POST /login` - Authenticate user
- `GET /logout` - End user session

### Dashboard & Actions
- `GET /dashboard` - User dashboard (requires authentication)
- `GET /log_action` - Action logging form (requires authentication)
- `POST /log_action` - Submit new sustainable action
- `GET /leaderboard` - Community leaderboard

### API
- `GET /api/dashboard_data` - JSON data for dashboard charts

## 🎨 Features in Detail

### User Dashboard
- **Personal Statistics**: Total points, actions completed, badges earned
- **Interactive Charts**: Category distribution and monthly activity trends
- **Recent Actions**: Timeline of user's sustainable activities
- **Progress Tracking**: Next badge milestones and weekly goals

### Action Logging
- **10 Action Categories**: Environmental, Transportation, Energy, etc.
- **Point Values**: Different actions award different points based on impact
- **Descriptions**: Optional detailed descriptions to inspire others
- **Real-time Preview**: See points and category before submitting

### Community Features
- **Real-time Leaderboard**: Updated instantly when users log actions
- **Badge System**: Visual achievements for reaching milestones
- **Recent Activity Feed**: See what others in the community are doing
- **Community Statistics**: Total users, actions, and impact points

## 🌱 Contributing

We welcome contributions to make EcoTrack even better! Here's how you can help:

### Reporting Issues
- Use GitHub Issues to report bugs or suggest features
- Provide detailed descriptions and steps to reproduce

### Code Contributions
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes with clear commit messages
4. Test your changes thoroughly
5. Submit a pull request with description of changes

### Areas for Contribution
- 🔧 Additional sustainable actions and point values
- 📊 More data visualizations and analytics
- 🎨 UI/UX improvements and animations
- 🔒 Enhanced security features
- 📱 Mobile app development
- 🌐 Internationalization and localization

## 🚀 Deployment

### Production Considerations
1. **Security**:
   - Change default secret key
   - Use environment variables for sensitive data
   - Implement HTTPS
   - Add rate limiting

2. **Database**:
   - Use MongoDB Atlas or properly secured MongoDB instance
   - Implement database backups
   - Add indexes for performance

3. **Hosting Options**:
   - **Heroku**: Easy deployment with MongoDB Atlas
   - **AWS**: EC2 with RDS or DocumentDB
   - **Digital Ocean**: Droplets with managed databases
   - **Vercel**: Serverless deployment

### Example Heroku Deployment
```bash
# Install Heroku CLI and login
heroku create ecotrack-app

# Set environment variables
heroku config:set MONGO_URI="your-mongodb-atlas-uri"
heroku config:set FLASK_SECRET_KEY="your-secret-key"

# Deploy
git push heroku main
```

## 📈 Future Enhancements

### Planned Features
- 📱 **Mobile App**: React Native or Flutter mobile application
- 👥 **Team Challenges**: Group competitions and challenges
- 📍 **Location-based Actions**: GPS-verified local actions
- 🔗 **Social Features**: Friend connections and social sharing
- 📊 **Advanced Analytics**: Environmental impact calculations
- 🎯 **Goal Setting**: Personal and community sustainability goals
- 🏪 **Marketplace**: Eco-friendly product recommendations
- 🎓 **Educational Content**: Sustainability tips and resources

### Technical Improvements
- 🔄 **Real-time Updates**: WebSocket integration for live updates
- 🎨 **Progressive Web App**: PWA features for offline usage
- 🔍 **Search & Filtering**: Advanced action search and filtering
- 📧 **Email Notifications**: Weekly summaries and achievement notifications
- 🔐 **OAuth Integration**: Google/Facebook login options
- 📊 **Data Export**: CSV/PDF export of personal statistics

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Acknowledgments

- **United Nations** - For the Sustainable Development Goals framework
- **MongoDB** - For the robust database platform
- **Flask Community** - For the excellent web framework
- **Bootstrap Team** - For the responsive UI framework
- **Chart.js** - For beautiful data visualizations
- **Font Awesome** - For the comprehensive icon library

## 📞 Support

- 📧 **Email**: support@ecotrack.app
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourusername/ecotrack/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/ecotrack/discussions)

---

**Made with 💚 for a sustainable future**

*EcoTrack - Making the world more sustainable, one action at a time.*