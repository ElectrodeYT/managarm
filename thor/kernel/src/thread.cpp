
#include "kernel.hpp"

namespace thor {

// --------------------------------------------------------
// Thread
// --------------------------------------------------------

Thread::Thread(KernelSharedPtr<Universe> &&universe,
		KernelSharedPtr<AddressSpace> &&address_space,
		KernelSharedPtr<RdFolder> &&directory)
: flags(0), p_universe(universe), p_addressSpace(address_space),
		p_directory(directory), p_joined(*kernelAlloc) { }

Thread::~Thread() {
	while(!p_joined.empty()) {
		JoinRequest request = p_joined.removeFront();

		UserEvent event(UserEvent::kTypeJoin, request.submitInfo);
		EventHub::Guard hub_guard(&request.eventHub->lock);
		request.eventHub->raiseEvent(hub_guard, frigg::move(event));
		hub_guard.unlock();
	}
}

void Thread::setThreadGroup(KernelSharedPtr<ThreadGroup> group) {
	p_threadGroup = frigg::move(group);
}

KernelUnsafePtr<ThreadGroup> Thread::getThreadGroup() {
	return p_threadGroup;
}
KernelUnsafePtr<Universe> Thread::getUniverse() {
	return p_universe;
}
KernelUnsafePtr<AddressSpace> Thread::getAddressSpace() {
	return p_addressSpace;
}
KernelUnsafePtr<RdFolder> Thread::getDirectory() {
	return p_directory;
}

void Thread::submitJoin(KernelSharedPtr<EventHub> event_hub,
		SubmitInfo submit_info) {
	p_joined.addBack(JoinRequest(frigg::move(event_hub), submit_info));
}

void Thread::enableIoPort(uintptr_t port) {
	p_saveState.threadTss.ioBitmap[port / 8] &= ~(1 << (port % 8));
}

void Thread::activate() {
	p_addressSpace->activate();
	p_saveState.activate();
}

void Thread::deactivate() {
	p_saveState.deactivate();
}

ThorRtThreadState &Thread::accessSaveState() {
	return p_saveState;
}

// --------------------------------------------------------
// Thread::JoinRequest
// --------------------------------------------------------

Thread::JoinRequest::JoinRequest(KernelSharedPtr<EventHub> event_hub,
		SubmitInfo submit_info)
: BaseRequest(frigg::move(event_hub), submit_info) { }

// --------------------------------------------------------
// ThreadGroup
// --------------------------------------------------------

void ThreadGroup::addThreadToGroup(KernelSharedPtr<ThreadGroup> group,
		KernelWeakPtr<Thread> thread) {
	KernelUnsafePtr<Thread> thread_ptr = thread;
	assert(!thread->getThreadGroup());
	group->p_members.push(frigg::move(thread));
	thread_ptr->setThreadGroup(frigg::move(group));
}

ThreadGroup::ThreadGroup()
: p_members(*kernelAlloc) { }

// --------------------------------------------------------
// ThreadQueue
// --------------------------------------------------------

ThreadQueue::ThreadQueue() { }

bool ThreadQueue::empty() {
	return p_front.get() == nullptr;
}

void ThreadQueue::addBack(KernelSharedPtr<Thread> &&thread) {
	// setup the back pointer before moving the thread pointer
	KernelUnsafePtr<Thread> back = p_back;
	p_back = thread;

	// move the thread pointer into the queue
	if(empty()) {
		p_front = frigg::move(thread);
	}else{
		thread->p_previousInQueue = back;
		back->p_nextInQueue = frigg::move(thread);
	}
}

KernelSharedPtr<Thread> ThreadQueue::removeFront() {
	assert(!empty());
	
	// move the front and second element out of the queue
	KernelSharedPtr<Thread> front = frigg::move(p_front);
	KernelSharedPtr<Thread> next = frigg::move(front->p_nextInQueue);
	front->p_previousInQueue = KernelUnsafePtr<Thread>();

	// fix the pointers to previous elements
	if(next.get() == nullptr) {
		p_back = KernelUnsafePtr<Thread>();
	}else{
		next->p_previousInQueue = KernelUnsafePtr<Thread>();
	}

	// move the second element back to the queue
	p_front = frigg::move(next);

	return front;
}

KernelSharedPtr<Thread> ThreadQueue::remove(KernelUnsafePtr<Thread> thread) {
	// move the successor out of the queue
	KernelSharedPtr<Thread> next = frigg::move(thread->p_nextInQueue);
	KernelUnsafePtr<Thread> previous = thread->p_previousInQueue;
	thread->p_previousInQueue = KernelUnsafePtr<Thread>();

	// fix pointers to previous elements
	if(p_back.get() == thread.get()) {
		p_back = previous;
	}else{
		next->p_previousInQueue = previous;
	}
	
	// move the successor back to the queue
	// move the thread out of the queue
	KernelSharedPtr<Thread> reference;
	if(p_front.get() == thread.get()) {
		reference = frigg::move(p_front);
		p_front = frigg::move(next);
	}else{
		reference = frigg::move(previous->p_nextInQueue);
		previous->p_nextInQueue = frigg::move(next);
	}

	return reference;
}

} // namespace thor

