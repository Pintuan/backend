-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Oct 14, 2024 at 10:56 AM
-- Server version: 10.4.27-MariaDB
-- PHP Version: 8.2.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `onekonekcrm`
--

-- --------------------------------------------------------

--
-- Table structure for table `accounts`
--

CREATE TABLE `accounts` (
  `serverConn` decimal(11,0) DEFAULT NULL,
  `currPlan` decimal(11,0) DEFAULT NULL,
  `accountId` decimal(15,0) NOT NULL,
  `billingDate` varchar(50) DEFAULT NULL,
  `stat` decimal(5,0) DEFAULT NULL,
  `userId` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `accounts`
--

INSERT INTO `accounts` (`serverConn`, `currPlan`, `accountId`, `billingDate`, `stat`, `userId`) VALUES
('17642231212', '10293312819', '125645685432', '16', '5522', '102339512332'),
('17642231212', '10293312817', '125645685433', '16', '5522', '102339512333'),
('17642231212', '10293312815', '125645685434', '16', '5522', '102339512334'),
('17642231212', '10293312817', '125645685435', '16', '5522', '102339512335'),
('17642231212', '10293312815', '125645685436', '16', '5522', '102339512336'),
('17642231212', '10293312815', '125645685437', '16', '5522', '102339512337'),
('17642231212', '10293312812', '125645685438', '16', '5522', '102339512338'),
('17642231212', '10293312812', '655123331235123', '14', '5522', '16458364911');

-- --------------------------------------------------------

--
-- Table structure for table `acounttype`
--

CREATE TABLE `acounttype` (
  `restrictionId` decimal(11,0) NOT NULL,
  `restrictionType` varchar(20) DEFAULT NULL,
  `position` varchar(20) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `acounttype`
--

INSERT INTO `acounttype` (`restrictionId`, `restrictionType`, `position`) VALUES
('25464136845', 'onr', 'Owner'),
('25464136855', 'cs', 'Customer'),
('25464136865', 'st', 'Staff'),
('99999999999', 'adn', 'Admin');

-- --------------------------------------------------------

--
-- Table structure for table `api`
--

CREATE TABLE `api` (
  `API_ID` decimal(10,0) NOT NULL,
  `API_NAME` varchar(255) NOT NULL,
  `PUBLIC_KEY` varchar(255) NOT NULL,
  `SECRET_KEY` varchar(255) NOT NULL,
  `webhookVerificationToken` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `api`
--

INSERT INTO `api` (`API_ID`, `API_NAME`, `PUBLIC_KEY`, `SECRET_KEY`, `webhookVerificationToken`) VALUES
('126343312', 'XENDIT', 'xnd_public_development_xtSYPoJVakMfTenAfERptlREtV3qKUp8FnxcaIsTfxuOHYzL24376lSg3nsT0', 'xnd_development_c9ixerSsua5IVmOMBg3SO51OWPh0aYA7X750CM2EErCA3DygsfBGAUXxUeJlV', 'gF6hHWvCLdtCTm3StGvykVReDbw9QQQhKtvVBS7jdtmjjsPt');

-- --------------------------------------------------------

--
-- Table structure for table `login`
--

CREATE TABLE `login` (
  `username` varchar(50) NOT NULL,
  `pWord` varchar(255) NOT NULL,
  `accountId` varchar(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `login`
--

INSERT INTO `login` (`username`, `pWord`, `accountId`) VALUES
('admin', '$2a$10$fhtur3P7CdE5eIAUdRu8QOHOd3ovmvBrCdSwncRWazL2uZ.0UC5Pa', '16458364951'),
('cs', '$2a$10$fhtur3P7CdE5eIAUdRu8QOHOd3ovmvBrCdSwncRWazL2uZ.0UC5Pa', '16458364911'),
('staff', '$2a$10$fhtur3P7CdE5eIAUdRu8QOHOd3ovmvBrCdSwncRWazL2uZ.0UC5Pa', '16458364981');

-- --------------------------------------------------------

--
-- Table structure for table `paymentoption`
--

CREATE TABLE `paymentoption` (
  `paymentID` decimal(10,0) NOT NULL,
  `paymentName` varchar(50) NOT NULL,
  `paymentLogo` blob DEFAULT NULL,
  `apiKey` decimal(10,0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `payments`
--

CREATE TABLE `payments` (
  `paymentId` decimal(15,0) NOT NULL,
  `accountId` decimal(15,0) DEFAULT NULL,
  `cashierId` varchar(50) DEFAULT NULL,
  `rebate` decimal(20,0) DEFAULT NULL,
  `totalPaid` decimal(20,0) DEFAULT NULL,
  `plan` decimal(11,0) DEFAULT NULL,
  `paymentDate` date DEFAULT NULL,
  `paymentType` decimal(10,0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `payments`
--

INSERT INTO `payments` (`paymentId`, `accountId`, `cashierId`, `rebate`, `totalPaid`, `plan`, `paymentDate`, `paymentType`) VALUES
('123233132231323', '655123331235123', '16458364981', '0', '1949', '10293312819', '2024-10-01', NULL),
('533421223888775', '655123331235123', '16458364981', '0', '1949', '10293312819', '2024-10-01', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `plans`
--

CREATE TABLE `plans` (
  `planId` decimal(11,0) NOT NULL,
  `planName` varchar(20) DEFAULT NULL,
  `planSpeed` decimal(10,0) DEFAULT NULL,
  `planPrice` decimal(10,0) DEFAULT NULL,
  `stat` decimal(5,0) DEFAULT 16340
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `plans`
--

INSERT INTO `plans` (`planId`, `planName`, `planSpeed`, `planPrice`, `stat`) VALUES
('10293312812', 'Sulit Plan', '75', '749', '16340'),
('10293312815', 'OK Plan', '100', '949', '16340'),
('10293312817', 'WOW Plan', '200', '1449', '16340'),
('10293312819', 'Panalo Plan', '300', '1949', '16340');

-- --------------------------------------------------------

--
-- Table structure for table `servers`
--

CREATE TABLE `servers` (
  `serverId` decimal(11,0) NOT NULL,
  `serverName` varchar(20) DEFAULT NULL,
  `serverLocation` varchar(50) DEFAULT NULL,
  `maxConn` decimal(10,0) DEFAULT NULL,
  `ipAdd` varchar(15) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `servers`
--

INSERT INTO `servers` (`serverId`, `serverName`, `serverLocation`, `maxConn`, `ipAdd`) VALUES
('17642231212', 'Palapat', 'Petro Jam, Palapat, Hagonoy, Bulacan', '1000', '192.168.62.15'),
('17642231213', 'San Sebastian', 'San Sebastian, Hagonoy, Bulacan', '1000', '192.168.22.12'),
('17642231215', 'Santa Elena', 'Sta Elena, Hagonoy, Bulacan', '1000', '192.168.63.5');

-- --------------------------------------------------------

--
-- Table structure for table `systemlogs`
--

CREATE TABLE `systemlogs` (
  `logId` decimal(30,0) NOT NULL,
  `userId` varchar(50) NOT NULL,
  `timedate` date NOT NULL DEFAULT current_timestamp(),
  `actionTaken` varchar(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tickets`
--

CREATE TABLE `tickets` (
  `accountId` decimal(15,0) DEFAULT NULL,
  `tickedId` decimal(11,0) NOT NULL,
  `ticketTitle` varchar(100) DEFAULT NULL,
  `ticketDescription` text DEFAULT NULL,
  `stat` decimal(2,0) DEFAULT NULL,
  `technicianId` decimal(15,0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `userId` varchar(50) NOT NULL,
  `firstName` varchar(50) DEFAULT NULL,
  `middleName` varchar(50) DEFAULT NULL,
  `lastName` varchar(50) DEFAULT NULL,
  `age` decimal(5,0) DEFAULT NULL,
  `email` varchar(50) DEFAULT NULL,
  `contactNum` decimal(11,0) DEFAULT NULL,
  `address` varchar(256) DEFAULT NULL,
  `profilePic` blob DEFAULT NULL,
  `restriction` decimal(11,0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`userId`, `firstName`, `middleName`, `lastName`, `age`, `email`, `contactNum`, `address`, `profilePic`, `restriction`) VALUES
('102339512332', 'Kaye Lyn', NULL, 'Pangan', '99', 'kayelynpangan@gmail.com', '9099999999', 'Abulalas, Hagonoy, Bulacan', NULL, '25464136855'),
('102339512333', 'Kaye Lyn', NULL, 'Pangan', '99', 'kayelynpangan@gmail.com', '9099999999', 'Abulalas, Hagonoy, Bulacan', NULL, '25464136855'),
('102339512334', 'Kaye Lyn', NULL, 'Pangan', '99', 'kayelynpangan@gmail.com', '9099999999', 'Abulalas, Hagonoy, Bulacan', NULL, '25464136855'),
('102339512335', 'Kaye Lyn', NULL, 'Pangan', '99', 'kayelynpangan@gmail.com', '9099999999', 'Abulalas, Hagonoy, Bulacan', NULL, '25464136855'),
('102339512336', 'Kaye Lyn', NULL, 'Pangan', '99', 'kayelynpangan@gmail.com', '9099999999', 'Abulalas, Hagonoy, Bulacan', NULL, '25464136855'),
('102339512337', 'Kaye Lyn', NULL, 'Pangan', '99', 'kayelynpangan@gmail.com', '9099999999', 'Abulalas, Hagonoy, Bulacan', NULL, '25464136855'),
('102339512338', 'Kaye Lyn', NULL, 'Pangan', '99', 'kayelynpangan@gmail.com', '9099999999', 'Abulalas, Hagonoy, Bulacan', NULL, '25464136855'),
('16458364911', 'Palapat', '', 'Customer', '0', '', '0', '', '', '25464136855'),
('16458364951', 'Dharist', '', 'Coronel', '42', '', '0', '', '', '99999999999'),
('16458364981', 'Main', '', 'Staff', '0', '', '0', '', '', '25464136865');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `accounts`
--
ALTER TABLE `accounts`
  ADD PRIMARY KEY (`accountId`),
  ADD UNIQUE KEY `userId` (`userId`),
  ADD KEY `serverConn` (`serverConn`),
  ADD KEY `currPlan` (`currPlan`);

--
-- Indexes for table `acounttype`
--
ALTER TABLE `acounttype`
  ADD PRIMARY KEY (`restrictionId`);

--
-- Indexes for table `api`
--
ALTER TABLE `api`
  ADD PRIMARY KEY (`API_ID`);

--
-- Indexes for table `login`
--
ALTER TABLE `login`
  ADD PRIMARY KEY (`username`),
  ADD KEY `accountId` (`accountId`);

--
-- Indexes for table `paymentoption`
--
ALTER TABLE `paymentoption`
  ADD PRIMARY KEY (`paymentID`),
  ADD KEY `apiKey_FK` (`apiKey`);

--
-- Indexes for table `payments`
--
ALTER TABLE `payments`
  ADD PRIMARY KEY (`paymentId`),
  ADD KEY `accountId` (`accountId`),
  ADD KEY `cashierId` (`cashierId`),
  ADD KEY `plan` (`plan`),
  ADD KEY `paymentType_FK` (`paymentType`);

--
-- Indexes for table `plans`
--
ALTER TABLE `plans`
  ADD PRIMARY KEY (`planId`);

--
-- Indexes for table `servers`
--
ALTER TABLE `servers`
  ADD PRIMARY KEY (`serverId`);

--
-- Indexes for table `systemlogs`
--
ALTER TABLE `systemlogs`
  ADD PRIMARY KEY (`logId`),
  ADD KEY `userId` (`userId`);

--
-- Indexes for table `tickets`
--
ALTER TABLE `tickets`
  ADD PRIMARY KEY (`tickedId`),
  ADD KEY `accountId` (`accountId`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`userId`),
  ADD KEY `fk_accountRestriction` (`restriction`);

--
-- Constraints for dumped tables
--

--
-- Constraints for table `accounts`
--
ALTER TABLE `accounts`
  ADD CONSTRAINT `accounts_ibfk_1` FOREIGN KEY (`userId`) REFERENCES `users` (`userId`),
  ADD CONSTRAINT `accounts_ibfk_2` FOREIGN KEY (`serverConn`) REFERENCES `servers` (`serverId`),
  ADD CONSTRAINT `accounts_ibfk_3` FOREIGN KEY (`currPlan`) REFERENCES `plans` (`planId`),
  ADD CONSTRAINT `accounts_ibfk_4` FOREIGN KEY (`currPlan`) REFERENCES `plans` (`planId`);

--
-- Constraints for table `login`
--
ALTER TABLE `login`
  ADD CONSTRAINT `login_ibfk_1` FOREIGN KEY (`accountId`) REFERENCES `users` (`userId`);

--
-- Constraints for table `paymentoption`
--
ALTER TABLE `paymentoption`
  ADD CONSTRAINT `apiKey_FK` FOREIGN KEY (`apiKey`) REFERENCES `api` (`API_ID`);

--
-- Constraints for table `payments`
--
ALTER TABLE `payments`
  ADD CONSTRAINT `paymentType_FK` FOREIGN KEY (`paymentType`) REFERENCES `paymentoption` (`paymentID`),
  ADD CONSTRAINT `payments_ibfk_1` FOREIGN KEY (`accountId`) REFERENCES `accounts` (`accountId`),
  ADD CONSTRAINT `payments_ibfk_2` FOREIGN KEY (`cashierId`) REFERENCES `users` (`userId`),
  ADD CONSTRAINT `payments_ibfk_3` FOREIGN KEY (`plan`) REFERENCES `plans` (`planId`);

--
-- Constraints for table `systemlogs`
--
ALTER TABLE `systemlogs`
  ADD CONSTRAINT `systemlogs_ibfk_1` FOREIGN KEY (`userId`) REFERENCES `users` (`userId`);

--
-- Constraints for table `tickets`
--
ALTER TABLE `tickets`
  ADD CONSTRAINT `tickets_ibfk_1` FOREIGN KEY (`accountId`) REFERENCES `accounts` (`accountId`);

--
-- Constraints for table `users`
--
ALTER TABLE `users`
  ADD CONSTRAINT `fk_accountRestriction` FOREIGN KEY (`restriction`) REFERENCES `acounttype` (`restrictionId`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
