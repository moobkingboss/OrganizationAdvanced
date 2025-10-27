// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * FHECheckinRegistry
 * -------------------
 * A privacy-first, FHE-enabled on-chain attendance (check-in) registry.
 *
 * Key ideas:
 *  - Individual check-ins are submitted with encrypted payloads (euint32 / ebool),
 *    so that sensitive fields are never revealed on-chain by default.
 *  - The contract maintains encrypted aggregate counters (e.g., total check-ins,
 *    per-tag counters), supporting privacy-preserving tally without exposing
 *    user-specific raw data.
 *  - Controlled decryption flows allow the reporter (or an authorized role) to
 *    request reveal of specific check-ins or aggregated counters when necessary.
 *  - "One check-in per address per day" guardrail is added to mimic typical
 *    attendance semantics and reduce spam.
 *
 * Notes on fhevm types:
 *  - euint32, ebool are encrypted integer/boolean types handled by fhevm.
 *  - FHE.asEuint32(<clear value>) creates a ciphertext from a clear value.
 *  - FHE.add / FHE.sub allow homomorphic addition/subtraction of ciphertexts.
 *  - FHE.toBytes32(euint32) converts a ciphertext into a bytes32 handle for IO.
 *  - FHE.requestDecryption(ciphertexts, selector) registers an off-chain decryption
 *    request; fhevm sequencer/oracle invokes the callback carrying cleartexts+proof.
 *  - FHE.checkSignatures(requestId, cleartexts, proof) validates authenticity.
 *
 * Dependencies:
 *  - "@fhevm/solidity" library and network config (SepoliaConfig used here).
 */

import { FHE, euint32, ebool } from "@fhevm/solidity/lib/FHE.sol";
import { SepoliaConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title FHE-enabled Check-in Registry (Anonymous)
/// @author …
contract FHECheckinRegistry is SepoliaConfig {
    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Encrypted check-in payload stored on-chain.
    /// @dev "tagCode" and "memoCode" are arbitrary application-level codings
    ///      decided by the front-end (e.g., hashing or mapping strings to u32).
    ///      "dayKey" is usually "floor(ts/86400)" or any bucketization chosen by client.
    struct EncryptedCheckin {
        uint256 id;          // sequential ID (monotonic)
        address reporter;    // sender wallet at submission time
        euint32 tagCode;     // encrypted tag/category code
        euint32 memoCode;    // encrypted memo/description code
        euint32 dayKey;      // encrypted day bucket (e.g., YYYYMMDD as u32)
        uint64  ts;          // timestamp (seconds)
        ebool   revoked;     // encrypted logical flag (revoked or not)
        bool    revealed;    // has the plaintext been revealed (optional)
    }

    /// @notice Decrypted details (only populated after explicit reveal).
    struct DecryptedCheckin {
        string tag;          // plaintext tag (optional)
        string memo;         // plaintext memo (optional)
        uint32 day;          // day bucket as clear integer (optional)
        bool   isRevealed;   // sealed once revealed
    }

    /// @notice Simple owner pattern without OZ dependency.
    address public owner;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    // Auto-incrementing primary key
    uint256 public checkinCount;

    // Per-ID encrypted records
    mapping(uint256 => EncryptedCheckin) public encryptedCheckins;

    // Optional clear reveals for specific IDs (only after request+callback)
    mapping(uint256 => DecryptedCheckin) public decryptedCheckins;

    // Encrypted aggregates
    euint32 private encTotal;                        // total count across all check-ins
    mapping(uint32 => euint32) private encPerTag;   // encrypted count per tag code
    mapping(uint32 => euint32) private encPerDay;   // encrypted count per day bucket

    // Book-keeping sets for UI convenience (clear lists are safe; contents are codes)
    // IMPORTANT: these are not sensitive themselves (just numeric codes).
    uint32[] private knownTagCodes;
    uint32[] private knownDayBuckets;
    mapping(uint32 => bool) private seenTag;
    mapping(uint32 => bool) private seenDay;

    // One-check-in-per-day guardrail
    mapping(address => uint64) public lastCheckinDay; // clear day index by address

    // Decryption routing
    // requestId -> payload (type id, subject id, or a composite key)
    // We use a compact envelope to support multiple request categories.
    enum ReqKind {
        Invalid,
        CheckinReveal,        // reveal a single check-in's fields
        AggregateTagCount,    // decrypt per-tag aggregate
        AggregateDayCount,    // decrypt per-day aggregate
        AggregateTotal        // decrypt global total
    }

    struct RequestKey {
        ReqKind kind;
        uint256 subject; // checkinId or (tagCode/day as uint256), or 0 for total
    }

    mapping(uint256 => RequestKey) private requestBook;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event CheckinSubmitted(uint256 indexed id, address indexed reporter, uint64 ts);
    event CheckinRevoked(uint256 indexed id);
    event RevealRequested(uint256 indexed id, uint256 requestId);
    event AggregatesRequested(ReqKind kind, uint256 subject, uint256 requestId);
    event CheckinRevealed(uint256 indexed id, string tag, string memo, uint32 day);
    event AggregateDecrypted(ReqKind kind, uint256 subject, uint32 clearCount);
    event OwnerTransferred(address indexed oldOwner, address indexed newOwner);

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyReporter(uint256 id) {
        require(encryptedCheckins[id].reporter != address(0), "Unknown checkin");
        require(encryptedCheckins[id].reporter == msg.sender, "Not reporter");
        _;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        owner = msg.sender;

        // Initialize encrypted totals to zero.
        encTotal = FHE.asEuint32(0);
        // per-tag / per-day counters are lazily initialized when first used.
    }

    /*//////////////////////////////////////////////////////////////
                               ADMIN / MISC
    //////////////////////////////////////////////////////////////*/

    /// @notice Return a simple OK to probe availability (UI handshake).
    function isAvailable() external pure returns (bool) {
        return true;
    }

    /// @notice Transfer ownership (simple admin capability).
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero addr");
        address old = owner;
        owner = newOwner;
        emit OwnerTransferred(old, newOwner);
    }

    /*//////////////////////////////////////////////////////////////
                              CHECK-IN LOGIC
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a new encrypted check-in.
     * @dev The front-end is responsible for FHE client work (key mgmt, encoding).
     *      - `tagCode` could encode category (e.g., conference, daily, remote...).
     *      - `memoCode` could encode short memo / opaque descriptor.
     *      - `dayKey` is a day bucket (e.g., 20250929) as u32.
     * Guardrails:
     *      - One check-in per address per day (enforced on clear "day index").
     *        For this, client must ALSO pass `clearDayIndex` (floor(ts/86400)).
     */
    function submitEncryptedCheckin(
        euint32 tagCode,
        euint32 memoCode,
        euint32 dayKey,
        uint32  clearDayIndex
    ) external {
        // One-per-day guard (address-level, clear day index).
        require(_canCheckin(msg.sender, clearDayIndex), "Already checked-in today");
        lastCheckinDay[msg.sender] = clearDayIndex;

        // Create the record
        uint256 newId = ++checkinCount;
        encryptedCheckins[newId] = EncryptedCheckin({
            id: newId,
            reporter: msg.sender,
            tagCode: tagCode,
            memoCode: memoCode,
            dayKey: dayKey,
            ts: uint64(block.timestamp),
            revoked: FHE.asEbool(false),
            revealed: false
        });

        // Aggregate updates (encrypted):
        // total++
        encTotal = FHE.add(encTotal, FHE.asEuint32(1));

        // For per-tag and per-day, we don't know clear values here.
        // Instead, we will **also** maintain mirror clear index sets for
        // user experience (list known tags/days) by asking the client to
        // provide their clear codes via helper functions (opt-in).
        // However, we can still keep the encrypted counters keyed by clear u32
        // (tag or day). See helper bumpers below.

        emit CheckinSubmitted(newId, msg.sender, uint64(block.timestamp));
    }

    /**
     * @notice Optional helper to bump encrypted aggregates when you already know
     *         the clear tag code or day bucket (u32). This is useful to keep
     *         aggregates consistent without decrypting individual entries.
     * @dev In a real pipeline, the client will call this immediately after
     *      submitEncryptedCheckin with the same clear codes it used to encrypt.
     */
    function bumpAggregates(uint32 clearTagCode, uint32 clearDayBucket) external {
        // bump per-tag
        if (!_seenTagCode(clearTagCode)) {
            seenTag[clearTagCode] = true;
            knownTagCodes.push(clearTagCode);
            // initialize counter lazily
            encPerTag[clearTagCode] = FHE.asEuint32(0);
        }
        encPerTag[clearTagCode] = FHE.add(encPerTag[clearTagCode], FHE.asEuint32(1));

        // bump per-day
        if (!_seenDayBucket(clearDayBucket)) {
            seenDay[clearDayBucket] = true;
            knownDayBuckets.push(clearDayBucket);
            // initialize counter lazily
            encPerDay[clearDayBucket] = FHE.asEuint32(0);
        }
        encPerDay[clearDayBucket] = FHE.add(encPerDay[clearDayBucket], FHE.asEuint32(1));
    }

    /**
     * @notice Allow the reporter to revoke their check-in before it has any
     *         regulatory/legal finalization. This toggles an encrypted flag and
     *         decrements aggregates. (Your business logic may forbid revoke.)
     * @dev For demonstration, we do not block revoke after reveal; adapt as needed.
     *      We assume the client also knows the clear tag/day to decrement aggregates.
     */
    function revokeCheckin(uint256 id, uint32 clearTagCode, uint32 clearDayBucket)
        external
        onlyReporter(id)
    {
        EncryptedCheckin storage rec = encryptedCheckins[id];
        // Mark revoked
        rec.revoked = FHE.asEbool(true);

        // Decrement aggregates
        // total--
        encTotal = FHE.sub(encTotal, FHE.asEuint32(1));

        // per-tag--
        if (_seenTagCode(clearTagCode)) {
            encPerTag[clearTagCode] = FHE.sub(encPerTag[clearTagCode], FHE.asEuint32(1));
        }
        // per-day--
        if (_seenDayBucket(clearDayBucket)) {
            encPerDay[clearDayBucket] = FHE.sub(encPerDay[clearDayBucket], FHE.asEuint32(1));
        }

        emit CheckinRevoked(id);
    }

    /*//////////////////////////////////////////////////////////////
                         DECRYPTION REQUEST FLOWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Reporter requests reveal (plaintext) for their own check-in.
     * @dev This builds a 3-field bundle [tagCode, memoCode, dayKey].
     *      The fhevm sequencer/oracle will invoke `decryptCheckinCallback`.
     */
    function requestCheckinReveal(uint256 id)
        external
        onlyReporter(id)
        returns (uint256 requestId)
    {
        EncryptedCheckin storage rec = encryptedCheckins[id];
        require(!rec.revealed, "Already revealed");

        bytes32;
        cts[0] = FHE.toBytes32(rec.tagCode);
        cts[1] = FHE.toBytes32(rec.memoCode);
        cts[2] = FHE.toBytes32(rec.dayKey);

        requestId = FHE.requestDecryption(cts, this.decryptCheckinCallback.selector);
        requestBook[requestId] = RequestKey({ kind: ReqKind.CheckinReveal, subject: id });

        emit RevealRequested(id, requestId);
    }

    /// @notice Callback invoked by fhevm with plaintexts + proof for a specific check-in reveal.
    function decryptCheckinCallback(
        uint256 requestId,
        bytes memory cleartexts,
        bytes memory proof
    ) external {
        RequestKey memory key = requestBook[requestId];
        require(key.kind == ReqKind.CheckinReveal, "Bad kind");
        uint256 id = key.subject;

        EncryptedCheckin storage rec = encryptedCheckins[id];
        require(rec.reporter != address(0), "Unknown id");
        require(!rec.revealed, "Already revealed");

        // Verify authenticity
        FHE.checkSignatures(requestId, cleartexts, proof);

        // Expected ABI shape: (string tag, string memo, uint32 day)
        (string memory tag, string memory memo, uint32 day) =
            abi.decode(cleartexts, (string, string, uint32));

        // Populate clear mirror (optional reveal)
        DecryptedCheckin storage d = decryptedCheckins[id];
        d.tag = tag;
        d.memo = memo;
        d.day  = day;
        d.isRevealed = true;

        // Seal the encrypted record as revealed (cannot reveal twice)
        rec.revealed = true;

        emit CheckinRevealed(id, tag, memo, day);
    }

    /**
     * @notice Request decryption of an encrypted aggregate (global).
     * @dev Returns requestId for the UI to track off-chain workflow.
     */
    function requestTotalCountDecryption() external returns (uint256 requestId) {
        bytes32;
        cts[0] = FHE.toBytes32(encTotal);
        requestId = FHE.requestDecryption(cts, this.decryptAggregateCallback.selector);
        requestBook[requestId] = RequestKey({ kind: ReqKind.AggregateTotal, subject: 0 });
        emit AggregatesRequested(ReqKind.AggregateTotal, 0, requestId);
    }

    /**
     * @notice Request decryption of a specific tag-code aggregate counter.
     * @param clearTagCode The tag code (u32) used to key the counter.
     */
    function requestTagCountDecryption(uint32 clearTagCode) external returns (uint256 requestId) {
        euint32 c = encPerTag[clearTagCode];
        require(FHE.isInitialized(c), "Tag counter not found");

        bytes32;
        cts[0] = FHE.toBytes32(c);
        requestId = FHE.requestDecryption(cts, this.decryptAggregateCallback.selector);
        requestBook[requestId] = RequestKey({ kind: ReqKind.AggregateTagCount, subject: uint256(clearTagCode) });
        emit AggregatesRequested(ReqKind.AggregateTagCount, uint256(clearTagCode), requestId);
    }

    /**
     * @notice Request decryption of a specific day-bucket aggregate counter.
     * @param clearDayBucket The day bucket (e.g., 20250929) as u32.
     */
    function requestDayCountDecryption(uint32 clearDayBucket) external returns (uint256 requestId) {
        euint32 c = encPerDay[clearDayBucket];
        require(FHE.isInitialized(c), "Day counter not found");

        bytes32;
        cts[0] = FHE.toBytes32(c);
        requestId = FHE.requestDecryption(cts, this.decryptAggregateCallback.selector);
        requestBook[requestId] = RequestKey({ kind: ReqKind.AggregateDayCount, subject: uint256(clearDayBucket) });
        emit AggregatesRequested(ReqKind.AggregateDayCount, uint256(clearDayBucket), requestId);
    }

    /**
     * @notice Unified callback for aggregate decryptions (total/tag/day).
     * @dev Expects a single uint32 in `cleartexts`.
     */
    function decryptAggregateCallback(
        uint256 requestId,
        bytes memory cleartexts,
        bytes memory proof
    ) external {
        RequestKey memory key = requestBook[requestId];
        require(key.kind != ReqKind.Invalid, "Unknown request");

        // Verify authenticity
        FHE.checkSignatures(requestId, cleartexts, proof);

        // Plain counter
        uint32 count = abi.decode(cleartexts, (uint32));
        emit AggregateDecrypted(key.kind, key.subject, count);
    }

    /*//////////////////////////////////////////////////////////////
                           READ-ONLY (VIEW) HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get an encrypted total as ciphertext (for client-side usage).
    function getEncryptedTotal() external view returns (euint32) {
        return encTotal;
    }

    /// @notice Get an encrypted per-tag counter.
    function getEncryptedPerTag(uint32 clearTagCode) external view returns (euint32) {
        return encPerTag[clearTagCode];
    }

    /// @notice Get an encrypted per-day counter.
    function getEncryptedPerDay(uint32 clearDayBucket) external view returns (euint32) {
        return encPerDay[clearDayBucket];
    }

    /// @notice Enumerate known tag codes (clear list for UX; values themselves are codes).
    function getKnownTagCodes() external view returns (uint32[] memory) {
        return knownTagCodes;
    }

    /// @notice Enumerate known day buckets (clear list for UX; values themselves are codes).
    function getKnownDayBuckets() external view returns (uint32[] memory) {
        return knownDayBuckets;
    }

    /// @notice Lightweight getter for a subset of EncryptedCheckin (without copying large structs).
    function getEncryptedCheckinHead(uint256 id)
        external
        view
        returns (address reporter, uint64 ts, bool revealed)
    {
        EncryptedCheckin storage r = encryptedCheckins[id];
        return (r.reporter, r.ts, r.revealed);
    }

    /// @notice Return ciphertext handles for a check-in (for advanced clients).
    function getEncryptedCheckinPayload(uint256 id)
        external
        view
        returns (bytes32 tagCtxt, bytes32 memoCtxt, bytes32 dayCtxt)
    {
        EncryptedCheckin storage r = encryptedCheckins[id];
        require(r.reporter != address(0), "Unknown id");
        return (FHE.toBytes32(r.tagCode), FHE.toBytes32(r.memoCode), FHE.toBytes32(r.dayKey));
    }

    /*//////////////////////////////////////////////////////////////
                               INTERNAL UTILS
    //////////////////////////////////////////////////////////////*/

    function _canCheckin(address user, uint32 dayIndex) internal view returns (bool) {
        return lastCheckinDay[user] != dayIndex;
    }

    function _seenTagCode(uint32 t) internal view returns (bool) {
        return seenTag[t];
    }

    function _seenDayBucket(uint32 d) internal view returns (bool) {
        return seenDay[d];
    }
}