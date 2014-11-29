/*
 * qca_safetimer.h - Qt Cryptographic Architecture
 * Copyright (C) 2014  Ivan Romanov <drizt@land.ru>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

#ifndef QCA_SAFETIMER_H
#define QCA_SAFETIMER_H

#include "qca_export.h"
#include <QObject>

class QEvent;
class QTimerEvent;

namespace QCA {

class QCA_EXPORT SafeTimer : public QObject
{
	Q_OBJECT
public:
	SafeTimer(QObject *parent = 0);
	~SafeTimer();

	int interval() const;
	bool isActive() const;
	bool isSingleShot() const;
	void setInterval(int msec);
	void setSingleShot(bool singleShot);
	int timerId() const;

public slots:
	void start(int msec);
	void start();
	void stop();

signals:
	void timeout();

protected:
	bool event(QEvent *event);
	void timerEvent(QTimerEvent *event);

private:
	// Functions is used internally. Outer world mustn't have access them.
	void startTimer() {}
	void killTimer(int) {}

	class Private;
	Private *d;
};

}

#endif // QCA_SAFETIMER_H
