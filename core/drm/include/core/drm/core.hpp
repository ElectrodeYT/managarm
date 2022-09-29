#pragma once

#include <queue>
#include <map>
#include <unordered_map>
#include <optional>
#include <variant>

#include <arch/mem_space.hpp>
#include <async/cancellation.hpp>
#include <async/recurring-event.hpp>
#include <async/oneshot-event.hpp>
#include <async/mutex.hpp>
#include <async/result.hpp>
#include <helix/memory.hpp>

#include "fwd-decls.hpp"

#include "device.hpp"
#include "id-allocator.hpp"
#include "range-allocator.hpp"
#include "property.hpp"

#include <libdrm/drm.h>
#include <libdrm/drm_mode.h>

#include <protocols/fs/defs.hpp>
#include <protocols/fs/server.hpp>

namespace drm_core {

enum struct ObjectType {
	encoder,
	connector,
	crtc,
	frameBuffer,
	plane
};

struct Event {
	uint64_t cookie;
	uint32_t crtcId;
	uint64_t timestamp;
};

struct BufferObject {
	BufferObject()
	: _mapping(-1) { }

protected:
	~BufferObject() = default;

public:
	virtual std::shared_ptr<BufferObject> sharedBufferObject() = 0;
	virtual size_t getSize() = 0;
	virtual std::pair<helix::BorrowedDescriptor, uint64_t> getMemory() = 0;

	void setupMapping(uint64_t mapping);
	uint64_t getMapping();

private:
	uint64_t _mapping;
};

struct Blob {
	Blob(std::vector<char> data)
	: _data(std::move(data)) {  };

	size_t size();
	const void *data();

private:
	std::vector<char> _data;
};

/**
 * This structure tracks DRM state per open file descriptor.
 */
struct File {
	File(std::shared_ptr<Device> device);

	static async::result<protocols::fs::ReadResult>

	/**
	 * A read operation on a DRM fd returning pending events, if any.
	 */
	read(void *object, const char *, void *buffer, size_t length);

	static async::result<helix::BorrowedDescriptor>
	accessMemory(void *object);

	static async::result<void>
	ioctl(void *object, managarm::fs::CntRequest req, helix::UniqueLane conversation);

	static async::result<frg::expected<protocols::fs::Error, protocols::fs::PollWaitResult>>
	pollWait(void *object, uint64_t sequence, int mask,
			async::cancellation_token cancellation);

	static async::result<frg::expected<protocols::fs::Error, protocols::fs::PollStatusResult>>
	pollStatus(void *object);

	void setBlocking(bool blocking);

	void attachFrameBuffer(std::shared_ptr<FrameBuffer> frame_buffer);
	void detachFrameBuffer(FrameBuffer *frame_buffer);
	const std::vector<std::shared_ptr<FrameBuffer>> &getFrameBuffers();

	/**
	 * Prepare a BufferObject to be mmap'ed by userspace.
	 *
	 * mmap()ing buffers works by providing a (fake) offset that can be used on the
	 * DRM fd to map the requested BufferObject. The (fake) offset is returned.
	 * Obviously, this offset is only valid on the DRM fd that is was set up on.
	 *
	 * @param bo BufferObject to be set up for mapping
	 * @return uint32_t The offset to be used to mmap the BufferObject
	 */
	uint32_t createHandle(std::shared_ptr<BufferObject> bo);
	BufferObject *resolveHandle(uint32_t handle);
	uint32_t getHandle(std::shared_ptr<drm_core::BufferObject> bo);

	bool exportBufferObject(uint32_t handle, std::array<char, 16> creds);

	std::pair<std::shared_ptr<drm_core::BufferObject>, uint32_t>
	importBufferObject(std::array<char, 16> creds);

	/**
	 * Add an @p event to the queue of pending events to be read by userspace.
	 *
	 * @param[in] event
	 */
	void postEvent(Event event);

	helix::BorrowedDescriptor statusPageMemory() {
		return _statusPage.getMemory();
	}

private:
	async::detached _retirePageFlip(std::unique_ptr<Configuration> config,
			uint64_t cookie, uint32_t crtc_id);

	std::shared_ptr<Device> _device;

	helix::UniqueDescriptor _memory;

	std::vector<std::shared_ptr<FrameBuffer>> _frameBuffers;

	// BufferObjects associated with this file.
	std::unordered_map<uint32_t, std::shared_ptr<BufferObject>> _buffers;
	// id allocator for mapping BufferObjects
	id_allocator<uint32_t> _allocator;

	// Event queuing structures.
	bool _isBlocking = true;
	std::deque<Event> _pendingEvents;
	uint64_t _eventSequence;
	async::recurring_event _eventBell;

	protocols::fs::StatusPageProvider _statusPage;

	bool universalPlanes;
	bool atomic;
};

struct PrimeFile {
	PrimeFile(helix::BorrowedDescriptor handle, size_t size);

	static async::result<helix::BorrowedDescriptor> accessMemory(void *object);

	static async::result<protocols::fs::SeekResult> seekAbs(void *object, int64_t offset);
	static async::result<protocols::fs::SeekResult> seekRel(void *object, int64_t offset);
	static async::result<protocols::fs::SeekResult> seekEof(void *object, int64_t offset);

	helix::BorrowedDescriptor _memory;

	size_t offset;
	size_t size;
};

struct Configuration {
	virtual ~Configuration() = default;

	virtual bool capture(std::vector<Assignment> assignment, std::unique_ptr<AtomicState> &state) = 0;
	virtual void dispose() = 0;
	virtual void commit(std::unique_ptr<AtomicState> &state) = 0;

	auto waitForCompletion() {
		return _ev.wait();
	}

protected:
	// TODO: Let derive classes handle the event?
	void complete() {
		_ev.raise();
	}

private:
	async::oneshot_event _ev;
};

/**
 * A ModeObject represents modeset objects visible to userspace.
 * It can represent Connectors, CRTCs, Encoders, Framebuffers and Planes.
 */
struct ModeObject {
	ModeObject(ObjectType type, uint32_t id)
	: _type(type), _id(id) { };

	virtual ~ModeObject() = default;

	uint32_t id();
	ObjectType type();

	Encoder *asEncoder();
	Connector *asConnector();
	Crtc *asCrtc();
	FrameBuffer *asFrameBuffer();
	Plane *asPlane();

	void setupWeakPtr(std::weak_ptr<ModeObject> self);
	std::shared_ptr<ModeObject> sharedModeObject();

	/**
	 * Get a vector of assignments for the ModeObject
	 *
	 * @param dev
	 * @return std::vector<drm_core::Assignment>
	 */
	virtual std::vector<drm_core::Assignment> getAssignments(std::shared_ptr<Device> dev);
private:
	ObjectType _type;
	uint32_t _id;
	std::weak_ptr<ModeObject> _self;
};

struct CrtcState {
	CrtcState(std::weak_ptr<Crtc> crtc);

	std::weak_ptr<Crtc> crtc(void);

	std::weak_ptr<Crtc> _crtc;
	bool active;

	bool planesChanged;
	bool modeChanged;
	bool activeChanged;
	bool connectorsChanged;
	uint32_t planeMask;
	uint32_t connectorMask;
	uint32_t encoderMask;

	std::shared_ptr<Blob> mode;
};

struct Crtc : ModeObject {
	Crtc(uint32_t id);

protected:
	~Crtc() = default;

public:
	void setupState(std::shared_ptr<Crtc> crtc);

	virtual Plane *primaryPlane() = 0;
	virtual Plane *cursorPlane();

	std::shared_ptr<drm_core::CrtcState> drmState();
	void setDrmState(std::shared_ptr<drm_core::CrtcState> new_state);

	std::vector<drm_core::Assignment> getAssignments(std::shared_ptr<Device> dev);

	int index;

private:
	std::shared_ptr<CrtcState> _drmState;
};

/**
 * The Encoder is responsible for converting a frame into the appropriate format for a connector.
 * Together with a Connector, it forms what xrandr would understand as an output.
 */
struct Encoder : ModeObject {
	Encoder(uint32_t id);

	drm_core::Crtc *currentCrtc();
	void setCurrentCrtc(drm_core::Crtc *crtc);
	void setupEncoderType(uint32_t type);
	uint32_t getEncoderType();
	void setupPossibleCrtcs(std::vector<Crtc *> crtcs);
	const std::vector<Crtc *> &getPossibleCrtcs();
	void setupPossibleClones(std::vector<Encoder *> clones);
	const std::vector<Encoder *> &getPossibleClones();

	int index;

private:
	drm_core::Crtc *_currentCrtc;
	uint32_t _encoderType;
	std::vector<Crtc *> _possibleCrtcs;
	std::vector<Encoder *> _possibleClones;
};

struct ConnectorState {
	ConnectorState(std::weak_ptr<Connector> connector) : connector(connector) {};

	std::shared_ptr<Connector> connector;
	std::shared_ptr<Crtc> crtc;
	std::shared_ptr<Encoder> encoder;
	uint32_t dpms;
};

/**
 * Represents a display connector.
 * It transmits the signal to the display, detects display connection and removal and exposes the display's supported modes.
 */
struct Connector : ModeObject {
	Connector(uint32_t id);

	void setupState(std::shared_ptr<drm_core::Connector> connector);

	const std::vector<drm_mode_modeinfo> &modeList();
	void setModeList(std::vector<drm_mode_modeinfo> mode_list);

	drm_core::Encoder *currentEncoder();
	void setCurrentEncoder(drm_core::Encoder *encoder);

	void setCurrentStatus(uint32_t status);
	uint32_t getCurrentStatus();

	void setupPossibleEncoders(std::vector<Encoder *> encoders);
	const std::vector<Encoder *> &getPossibleEncoders();

	void setupPhysicalDimensions(uint32_t width, uint32_t height);
	uint32_t getPhysicalWidth();
	uint32_t getPhysicalHeight();
	void setupSubpixel(uint32_t subpixel);
	uint32_t getSubpixel();
	void setConnectorType(uint32_t type);
	uint32_t connectorType();

	std::shared_ptr<drm_core::ConnectorState> drmState();
	void setDrmState(std::shared_ptr<drm_core::ConnectorState> new_state);

	std::vector<drm_core::Assignment> getAssignments(std::shared_ptr<Device> dev);

private:
	std::vector<drm_mode_modeinfo> _modeList;
	drm_core::Encoder *_currentEncoder;
	uint32_t _currentStatus;
	std::vector<Encoder *> _possibleEncoders;
	uint32_t _physicalWidth;
	uint32_t _physicalHeight;
	uint32_t _subpixel;
	uint32_t _connectorType;

	std::shared_ptr<ConnectorState> _drmState;
};

/**
 * Holds all info relating to a framebuffer, such as size and pixel format.
 */
struct FrameBuffer : ModeObject {
	FrameBuffer(uint32_t id);

protected:
	~FrameBuffer() = default;

public:
	virtual void notifyDirty() = 0;
};

struct Plane : ModeObject {
	enum struct PlaneType {
		OVERLAY = 0,
		PRIMARY = 1,
		CURSOR = 2,
	};

	Plane(uint32_t id, PlaneType type);

	void setupState(std::shared_ptr<Plane> plane);

	std::vector<drm_core::Assignment> getAssignments(std::shared_ptr<Device> dev);

	PlaneType type();

	void setCurrentFrameBuffer(drm_core::FrameBuffer *crtc);
	drm_core::FrameBuffer *getFrameBuffer();

	void setupPossibleCrtcs(std::vector<Crtc *> crtcs);
	const std::vector<Crtc *> &getPossibleCrtcs();

	std::shared_ptr<drm_core::PlaneState> drmState();
	void setDrmState(std::shared_ptr<drm_core::PlaneState> new_state);

private:
	PlaneType _type;
	drm_core::FrameBuffer *_fb;
	std::vector<Crtc *> _possibleCrtcs;
	std::shared_ptr<PlaneState> _drmState;
};

struct PlaneState {
	PlaneState(std::weak_ptr<Plane> plane) : plane(plane) {};

	Plane::PlaneType type(void);

	std::shared_ptr<Plane> plane;
	std::shared_ptr<Crtc> crtc;
	std::shared_ptr<FrameBuffer> fb;
	int32_t crtc_x;
	int32_t crtc_y;
	uint32_t crtc_w;
	uint32_t crtc_h;
	uint32_t src_x;
	uint32_t src_y;
	uint32_t src_w;
	uint32_t src_h;
};

async::detached serveDrmDevice(std::shared_ptr<drm_core::Device> device,
		helix::UniqueLane lane);

// ---------------------------------------------
// Formats
// ---------------------------------------------

uint32_t convertLegacyFormat(uint32_t bpp, uint32_t depth);

struct FormatInfo {
	int cpp;
};

std::optional<FormatInfo> getFormatInfo(uint32_t fourcc);

drm_mode_modeinfo makeModeInfo(const char *name, uint32_t type,
		uint32_t clock, unsigned int hdisplay, unsigned int hsync_start,
		unsigned int hsync_end, unsigned int htotal, unsigned int hskew,
		unsigned int vdisplay, unsigned int vsync_start, unsigned int vsync_end,
		unsigned int vtotal, unsigned int vscan, uint32_t flags);

void addDmtModes(std::vector<drm_mode_modeinfo> &supported_modes,
		unsigned int max_width, unsigned max_height);

// Copies 16-byte aligned buffers. Expected to be faster than plain memcpy().
extern "C" void fastCopy16(void *, const void *, size_t);

} //namespace drm_core

