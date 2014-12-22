#ifndef SPLASHSCREEN_H
#define SPLASHSCREEN_H

#include <QSplashScreen>
#include <QTimer>
#define COPYRIGHT_YEAR 2014

/** class for the splashscreen with information of the running client
 */
class SplashScreen : public QSplashScreen
{
    Q_OBJECT

public:
	QTimer *movieTimer;
    explicit SplashScreen(const QPixmap &pixmap = QPixmap(), Qt::WindowFlags f = 0);
	void DelayFinish(QWidget *wMain, int deLay=2);
public slots:
	void finishSplashTimer();
};

#endif // SPLASHSCREEN_H
