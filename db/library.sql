-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Nov 25, 2024 at 05:04 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `library`
--

-- --------------------------------------------------------

--
-- Table structure for table `admin`
--

CREATE TABLE `admin` (
  `admin_id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admin`
--

INSERT INTO `admin` (`admin_id`, `username`, `password`) VALUES
(2, 'admin', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'),
(3, 'adminls', '$2y$10$ZveooWMnBvZ0Cv.tm.n.yOAGhpw2rHVBsb/Jbsm7PvTh9vapHSt3W');

-- --------------------------------------------------------

--
-- Table structure for table `authors`
--

CREATE TABLE `authors` (
  `authorid` int(9) NOT NULL,
  `name` char(255) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `disabled` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `authors`
--

INSERT INTO `authors` (`authorid`, `name`, `username`, `password`, `disabled`) VALUES
(5, 'Rosemar (Rose and Bruno Mars)', '', '', 0),
(6, 'UserName', 'testusers', 'e0e6097a6f8af07daf5fc7244336ba37133713a8fc7345c36d667dfa513fabaa', 0),
(7, 'John Doe', 'johndoe', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 0);

-- --------------------------------------------------------

--
-- Table structure for table `books`
--

CREATE TABLE `books` (
  `bookid` int(9) NOT NULL,
  `authorid` int(11) NOT NULL,
  `title` char(255) NOT NULL,
  `content` text NOT NULL,
  `archived` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `books`
--

INSERT INTO `books` (`bookid`, `authorid`, `title`, `content`, `archived`) VALUES
(2, 5, 'Apateu Apateu APT', '[Intro]\r\nChaeyeongiga joahaneun raendeom geim\r\nRaendeom geim\r\nGame start\r\n\r\n[Chorus: ROSÉ]\r\nApateu, apateu\r\nApateu, apateu\r\nApateu, apateu\r\nUh, uh-huh, uh-huh\r\nApateu, apateu\r\nApateu, apateu\r\nApateu, apateu\r\nUh, uh-huh, uh-huh\r\n\r\n[Verse 1: ROSÉ]\r\nKissy face, kissy face\r\nSent to your phone, but\r\nI\'m tryna kiss your lips for real (Uh-huh, uh-huh)\r\nRed hearts, red hearts\r\nThat\'s what I\'m on, yeah\r\nCome give me somethin\' I can feel, oh-oh, oh\r\n\r\n[Pre-Chorus: ROSÉ]\r\nDon\'t you want me like I want you, baby?\r\nDon\'t you need me like I need you now?\r\nSleep tomorrow, but tonight, go crazy\r\nAll you gotta do is just meet me at the\r\nSee upcoming pop shows\r\nGet tickets for your favorite artists\r\nYou might also like\r\nDie With A Smile\r\nLady Gaga & Bruno Mars\r\nMantra\r\nJENNIE\r\nAPT.\r\nROSÉ & Bruno Mars\r\n[Chorus: ROSÉ]\r\nApatеu, apateu\r\nApateu, apateu\r\nApatеu, apateu\r\nUh, uh-huh, uh-huh\r\nApateu, apateu\r\nApateu, apateu\r\nApateu, apateu\r\nUh, uh-huh, uh-huh\r\n\r\n[Verse 2: Bruno Mars, Bruno Mars & ROSÉ]\r\nIt\'s whatever (Whatever), it\'s whatever (Whatever)\r\nIt\'s whatever (Whatever) you like (Woo)\r\nTurn this apateu into a club (Uh-huh, uh-huh)\r\nI\'m talkin\' drink, dance, smoke, freak, party all night (Come on)\r\nGeonbae, geonbae, girl, what\'s up? Oh-oh, oh\r\n\r\n[Pre-Chorus: Bruno Mars & ROSÉ]\r\nDon\'t you want me like I want you, baby?\r\nDon\'t you need me like I need you now?\r\nSleep tomorrow, but tonight, go crazy\r\nAll you gotta do is just meet me at the\r\n\r\n[Chorus: ROSÉ & Bruno Mars]\r\nApateu, apateu\r\nApateu, apateu\r\nApateu, apateu\r\nUh, uh-huh, uh-huh\r\nApateu, apateu\r\nApateu, apateu\r\nApateu, apateu\r\nUh, uh-huh, uh-huh\r\n[Bridge: ROSÉ, ROSÉ & Bruno Mars]\r\nHey, so now you know the game\r\nAre you ready?\r\n\'Cause I\'m comin\' to get ya, get ya, get ya\r\nHold on, hold on\r\nI\'m on my way\r\nYeah, yeah, yeah-yeah, yeah\r\nI\'m on my way\r\nHold on, hold on\r\nI\'m on my way\r\nYeah, yeah, yeah-yeah, yeah\r\nI\'m on my way\r\n\r\n[Pre-Chorus: ROSÉ & Bruno Mars]\r\nDon\'t you want me like I want you, baby?\r\nDon\'t you need me like I need you now?\r\nSleep tomorrow, but tonight, go crazy\r\nAll you gotta do is just meet me at the\r\n\r\n[Chorus: ROSÉ & Bruno Mars, ROSÉ, Bruno Mars]\r\nApateu, apateu\r\nApateu, apateu\r\nApateu, apateu\r\nJust meet me at the (Uh, uh-huh, uh-huh)\r\nApateu, apateu\r\nApateu, apateu\r\nApateu, apateu\r\nJust meet me at the (Uh, uh-huh, uh-huh)\r\nApateu, apateu\r\nApateu, apateu\r\nApateu, apateu\r\nJust meet me at the (Uh, uh-huh, uh-huh)\r\nApateu, apateu\r\nApateu, apateu\r\nApateu, apateu\r\nUh, uh-huh, uh-huh', 1);

-- --------------------------------------------------------

--
-- Table structure for table `book_authors`
--

CREATE TABLE `book_authors` (
  `collectionid` int(9) NOT NULL,
  `authorid` int(9) NOT NULL,
  `bookid` int(9) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `userid` int(9) NOT NULL,
  `username` char(255) NOT NULL,
  `password` text NOT NULL,
  `status` enum('enabled','disabled') DEFAULT 'enabled'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`userid`, `username`, `password`, `status`) VALUES
(16, 'testusers', 'e0e6097a6f8af07daf5fc7244336ba37133713a8fc7345c36d667dfa513fabaa', 'enabled'),
(17, 'johnallenc', '877c7d40675dea1a5c510a79105259616562bda39304090068953503f3f3d6c4', ''),
(18, 'testuserss', 'e0e6097a6f8af07daf5fc7244336ba37133713a8fc7345c36d667dfa513fabaa', 'disabled');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admin`
--
ALTER TABLE `admin`
  ADD PRIMARY KEY (`admin_id`);

--
-- Indexes for table `authors`
--
ALTER TABLE `authors`
  ADD PRIMARY KEY (`authorid`);

--
-- Indexes for table `books`
--
ALTER TABLE `books`
  ADD PRIMARY KEY (`bookid`),
  ADD KEY `authorid` (`authorid`);

--
-- Indexes for table `book_authors`
--
ALTER TABLE `book_authors`
  ADD PRIMARY KEY (`collectionid`),
  ADD KEY `bookid` (`bookid`),
  ADD KEY `authorid` (`authorid`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`userid`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admin`
--
ALTER TABLE `admin`
  MODIFY `admin_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `authors`
--
ALTER TABLE `authors`
  MODIFY `authorid` int(9) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `books`
--
ALTER TABLE `books`
  MODIFY `bookid` int(9) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `book_authors`
--
ALTER TABLE `book_authors`
  MODIFY `collectionid` int(9) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `userid` int(9) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `books`
--
ALTER TABLE `books`
  ADD CONSTRAINT `books_ibfk_1` FOREIGN KEY (`authorid`) REFERENCES `authors` (`authorid`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `book_authors`
--
ALTER TABLE `book_authors`
  ADD CONSTRAINT `book_authors_ibfk_1` FOREIGN KEY (`bookid`) REFERENCES `books` (`bookid`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `book_authors_ibfk_2` FOREIGN KEY (`authorid`) REFERENCES `authors` (`authorid`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
