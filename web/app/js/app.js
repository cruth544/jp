import _ from 'lodash'
require( 'index.html' )
require( 'css/_globals.scss' )
require( 'css/main.scss' )

!(function () {
	const TOP_TRIGGER = 50
	const NAV_LINKS = [
		'HELLO!',
		'WHEN & WHERE',
		'WHERE TO STAY',
		'IRVINE',
		'CELEBRATION',
		'OUR JOURNEY',
		'REGISTRY',
		'RSVP'
	]

	function init() {
		var ul = document.querySelectorAll( '#nav-bar .nav-list' )
		if ( ul ) ul = ul[0]

		NAV_LINKS.forEach( function ( link ) {
			var li = document.createElement( 'li' )
			li.setAttribute( 'class', 'link nav-link' )
			li.innerText = link
			li.addEventListener( 'click', onNavClick )
			ul.append( li )
		})

		console.log( ul )
	}
	init()

	var gondola = document.getElementById( 'gondola' )
	var mountains = _.map( document.getElementsByClassName( 'mountain' ) )
	window.addEventListener( 'load', function ( e ) {
		window.scrollTo( 0, Number.MAX_VALUE )
		document.getElementsByTagName( 'main' )[0].className = 'scene fade-in'
	})

	var height = document.body.clientHeight
	var center = mountains[0]
	var left = mountains[1]
	var right = mountains[2]

	var info = document.getElementById( 'info-overlay' )


	window.addEventListener( 'scroll', function ( e ) {
		var currentY = window.top.scrollY
		var winHeight = window.screen.height
		var percent = ( 1 - ( currentY + winHeight ) / height ) / 1.5

		left.translateX = 150 * percent * -1
		left.translateY = 0

		right.translateX = 150 * percent
		right.translateY = 0

		center.translateX = percent * -10
		center.translateY = percent * 100 / 3

		left.scale = percent + 2.4
		right.scale = percent + 2.4
		center.scale = percent * 6 + 2.4

		checkTop( currentY )
	})

	function frame( time ) {
		mountains.forEach( function ( mount ) {
			var transform = 'scale('+ mount.scale +')'
			transform += ' translateX('+ mount.translateX +'%)'
			transform += ' translateY('+ mount.translateY +'%)'

			mount.style.transform = transform
		})
		requestAnimationFrame( frame )
	}
	requestAnimationFrame( frame )

	function checkTop( y ) {
		if ( y < TOP_TRIGGER ) {
			info.style.opacity = '1'
			info.style.visibility = 'visible'
			document.body.style.backgroundColor = 'white'
		} else {
			info.style.opacity = '0'
			document.body.style.backgroundColor = 'skyblue'
		}
	}

	function onNavClick( nav ) {
		console.log( nav )
	}







	window.left = left
	window.right = right
	window.center = center
	window.mountains = mountains


	window.addEventListener( 'beforeunload', function ( e ) {
		window.scrollTo( 0, Number.MAX_VALUE )
	})
})()
