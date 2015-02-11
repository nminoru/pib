/*
 * pib_spinlock.h - Recursive pinlock declarations for pib
 *
 * Copyright (c) 2015 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#ifndef PIB_SPINLOCK_H
#define PIB_SPINLOCK_H

#include <linux/spinlock.h>
#include <linux/sched.h>

struct pib_spinlock {
	spinlock_t		lock;
	struct task_struct     *owner;
	int			depth;
};

typedef struct pib_spinlock pib_spinlock_t;

#define pib_spin_lock_init(lockp)			\
do {							\
	spin_lock_init(&(lockp)->lock);			\
	(lockp)->owner = NULL;				\
	(lockp)->depth = 0;				\
} while (0)

#define pib_spin_lock(lockp)				\
do {							\
	if ((lockp)->owner != current) {		\
		spin_lock(&(lockp)->lock);		\
		(lockp)->owner = current;		\
	}						\
	(lockp)->depth++;				\
} while (0)

#define pib_spin_unlock(lockp)				\
do {							\
	(lockp)->depth--;				\
	if ((lockp)->depth == 0) {			\
		(lockp)->owner = NULL;			\
		spin_unlock(&(lockp)->lock);		\
	}						\
} while (0)

#define pib_spin_lock_irqsave(lockp, flags)		\
do {							\
	if ((lockp)->owner != current) {		\
		spin_lock_irqsave(&(lockp)->lock, flags); \
		(lockp)->owner = current;		\
	} else {					\
		(flags) = 0; /* keep compiler quiet */	\
	}						\
	(lockp)->depth++;				\
} while (0)

#define pib_spin_unlock_irqrestore(lockp, flags)	\
do {							\
	(lockp)->depth--;				\
	if ((lockp)->depth == 0) {			\
		(lockp)->owner = NULL;			\
		spin_unlock_irqrestore(&(lockp)->lock, flags); \
	}						\
} while (0)

static inline int pib_spin_is_locked(pib_spinlock_t *lockp)
{
	return spin_is_locked(&lockp->lock);
}

#endif /* PIB_SPINLOCK_H */
