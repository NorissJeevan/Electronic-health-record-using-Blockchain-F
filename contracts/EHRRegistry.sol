// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title EHRRegistry
 * @dev Manages user roles, health record hashes, and access permissions on the blockchain.
 */
contract EHRRegistry {

    enum Role { Patient, Doctor, Admin }

    struct User {
        string mailId;      // Off-chain identifier
        Role role;          // User's role
        bool isRegistered;  // Flag to check if user exists
    }

    struct Record {
        address issuer;     // Address of the Doctor or Admin who added the record
        uint256 timestamp;  // Time of issuance
        bytes32 dataHash;   // SHA-256 hash of the medical record data
        address patient;    // The patient this record belongs to
    }

    // Mapping from an Ethereum address to a User struct
    mapping(address => User) public users;

    // Mapping from a record hash to the full Record struct
    mapping(bytes32 => Record) public records;

    // Mapping to control access: recordHash => doctor/admin_address => hasAccess
    mapping(bytes32 => mapping(address => bool)) public accessControl;

    // Event logs for off-chain monitoring
    event UserRegistered(address indexed userAddress, string mailId, Role role);
    event RecordAdded(bytes32 indexed recordHash, address indexed patient, address indexed issuer);
    event AccessGranted(bytes32 indexed recordHash, address indexed grantee, address indexed granter);

    address public owner; // The contract deployer, likely the main hospital system

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the contract owner can perform this action.");
        _;
    }

    modifier isRegisteredUser() {
        require(users[msg.sender].isRegistered, "User is not registered.");
        _;
    }

    /**
     * @dev Registers a new user (Patient, Doctor, or Admin).
     * Can be called by anyone, simulating a public registration form.
     */
    function registerUser(string memory _mailId, Role _role) public {
        require(!users[msg.sender].isRegistered, "User address already registered.");
        users[msg.sender] = User({
            mailId: _mailId,
            role: _role,
            isRegistered: true
        });
        emit UserRegistered(msg.sender, _mailId, _role);
    }

    /**
     * @dev Adds a new medical record hash to the blockchain.
     * Only callable by registered Doctors or Admins.
     */
    function addRecord(bytes32 _recordHash, address _patientAddress) public isRegisteredUser {
        require(users[msg.sender].role == Role.Doctor || users[msg.sender].role == Role.Admin, "Only Doctors or Admins can add records.");
        require(users[_patientAddress].role == Role.Patient, "Records can only be added for patients.");
        require(records[_recordHash].issuer == address(0), "Record with this hash already exists.");

        records[_recordHash] = Record({
            issuer: msg.sender,
            timestamp: block.timestamp,
            dataHash: _recordHash,
            patient: _patientAddress
        });

        // The patient automatically has access to their own record
        accessControl[_recordHash][msg.sender] = true;
        accessControl[_recordHash][_patientAddress] = true;

        emit RecordAdded(_recordHash, _patientAddress, msg.sender);
    }

    /**
     * @dev Grants access to a medical record.
     * Only callable by the patient who owns the record.
     */
    function grantAccess(bytes32 _recordHash, address _grantee) public isRegisteredUser {
        require(records[_recordHash].patient == msg.sender, "Only the patient can grant access to their records.");
        require(users[_grantee].role == Role.Doctor || users[_grantee].role == Role.Admin, "Access can only be granted to Doctors or Admins.");

        accessControl[_recordHash][_grantee] = true;
        emit AccessGranted(_recordHash, _grantee, msg.sender);
    }

    /**
     * @dev Checks if a user has access to a specific record.
     */
    function checkAccess(bytes32 _recordHash, address _userAddress) public view returns (bool) {
        return accessControl[_recordHash][_userAddress];
    }
}